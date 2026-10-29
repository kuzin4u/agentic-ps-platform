// Программа оператора для приёмки песочницы (SANDBOX-ACC, решение владельца 28.10): допуск тестового агента и отзыв его
// сертификата поверх dist установленной версии — допуска по HTTP нет до PS-31 (расхождение № 9). На VPS скрипт приёмки
// копирует её по ssh во временный каталог и удаляет после работы; установка не меняется. В CI — та же программа локально.
// Закрытых ключей агента здесь нет — только открытый ключ и CSR; ключ УЦ не покидает машину. Вывод — одна строка JSON,
// отказ — { error: <код> } без текста исключения.
//
// Запуск: node operator.mjs <корень установки> <EnvironmentFile unit | -> ; запрос — JSON в stdin:
//   { "cmd": "admit", "application": { ... } }   { "cmd": "revoke", "serial": "<hex>" }
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/** Оператор тестовых агентов в записи реестра (контекст допуска, не тело заявления). */
const OPERATOR = "op-acceptance";

const reply = (body, code = 0) => {
  process.stdout.write(`${JSON.stringify(body)}\n`);
  process.exit(code);
};
const fail = (error) => reply({ error }, 1);
const errCode = (e) => e?.reason ?? e?.code ?? e?.name ?? "UNKNOWN";

const [root, envFile] = process.argv.slice(2);
if (!root || !envFile) fail("USAGE");

// EnvironmentFile unit systemd: строки KEY=VALUE, # — комментарий; значение в кавычках — без кавычек.
if (envFile !== "-") {
  let text = "";
  try {
    text = readFileSync(envFile, "utf8");
  } catch (e) {
    fail(`ENV_FILE_${errCode(e)}`);
  }
  for (const line of text.split("\n")) {
    const m = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (m) process.env[m[1]] = m[2].replace(/^(["'])(.*)\1$/, "$2");
  }
}
// Только песочница: УЦ и обязательный CSR есть только в sandbox (РП66 п. 3, 6), иначе — отказ, а не допуск без сертификата.
if (process.env.PLATFORM_ENV !== "sandbox") fail("ENV_NOT_SANDBOX");
if (!process.env.DATABASE_URL) fail("DATABASE_URL_MISSING");

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
let req;
try {
  req = JSON.parse(Buffer.concat(chunks).toString("utf8"));
} catch {
  fail("REQUEST_INVALID");
}

const dist = (p) => import(pathToFileURL(join(root, "dist", p)).href);
let pool;
try {
  const { AgentRegistry, PgAgentRegistryStore, loadCaFile } = await dist("registry/index.js");
  const { loadParams } = await dist("shared/config.js");
  // pg — из node_modules установки, той же версии, что у сервиса.
  const pg = createRequire(join(root, "package.json"))("pg");
  const params = loadParams();
  pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
  // Реестр — как в main.ts sandbox: УЦ из файла, CSR обязателен (РП66 п. 3).
  const registry = new AgentRegistry(new PgAgentRegistryStore(pool), {
    keys: params,
    certificates: {
      ca: loadCaFile(process.env.PLATFORM_CA_KEY_PATH, new Date()),
      ttlDays: params.agent_cert_ttl_days,
      backdateSec: params.cert_not_before_backdate_sec,
      required: true,
    },
  });

  if (req?.cmd === "admit" && typeof req.application === "object" && req.application !== null) {
    const d = await registry.admit(req.application, { contour: "sandbox", operator: OPERATOR });
    await pool.end();
    if (!d.admitted) reply({ admitted: false, reasons: d.reasons });
    reply({
      admitted: true,
      agent_code: d.record.agent_code,
      ...(d.certificate ? { certificate: { serial: d.certificate.serial, der: d.certificate.der, not_after: d.certificate.not_after } } : {}),
    });
  } else if (req?.cmd === "revoke" && typeof req.serial === "string") {
    const r = await registry.revokeCertificate(req.serial);
    await pool.end();
    reply({ revoked: r !== undefined && r.revoked_at !== null });
  } else {
    await pool.end();
    fail("REQUEST_INVALID");
  }
} catch (e) {
  await pool?.end().catch(() => {});
  // 42P01 (таблицы нет) — схема не размечена: сервис ещё ни разу не запускался, миграции применяет он при запуске
  // (SANDBOX-ACC К2.1а; сессия 57 К4.2). Понятный код вместо кода PostgreSQL; прочие коды — как есть.
  fail(e?.code === "42P01" ? "SCHEMA_NOT_READY" : String(errCode(e)));
}
