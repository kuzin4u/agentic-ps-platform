// Самопроверка приёмки песочницы на PostgreSQL (SANDBOX-ACC К2.1; список КТ1 «что должен покрыть К2.1», PR #82):
// operator.mjs по-настоящему поверх собранного dist и PG; runAcceptance против процесса src/main.ts sandbox (TLS, ступень 0,
// реестр на PG) с портом оператора на этой машине — operator.mjs, журнал — stdout процесса, перезапуск — новый процесс на
// том же порту; кавычки удалённой строки sshOperator — настоящим sh -c без ssh. Окружение operator.mjs — только из
// EnvironmentFile (с кавычками и комментариями, абсолютный PARAMS_PATH), у сервиса — те же значения напрямую, как у
// systemd. В CI (РП30 п. 7, dist собран до тестов); локально без базы — пропуск.
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { accepted, CHECK_IDS, report, runAcceptance } from "../../scripts/acceptance/checks.js";
import { OPERATOR_PROGRAM, parseReply, spawnExec, sshOperator, type Exec, type OperatorPort } from "../../scripts/acceptance/operator.js";
import { initCaFile } from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import { applyPlatformMigrations } from "../../src/shared/migrations.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { newCsr } from "../support/csr.js";
import { DATABASE_URL } from "../support/pg.js";

/** Корень установки — этот репозиторий: dist, node_modules, package.json. */
const ROOT = fileURLToPath(new URL("../..", import.meta.url)).replace(/\/$/, "");
/** Срок сертификата агента в своих параметрах: по нему видно, что operator.mjs прочитал PARAMS_PATH из файла. */
const TTL_DAYS = 7;

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      s.close(() => (typeof addr === "object" && addr ? resolve(addr.port) : reject(new Error("порт не получен"))));
    });
  });

const stop = (child: ChildProcess): Promise<number | null> =>
  new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve(child.exitCode);
    child.once("exit", (code) => resolve(code));
    child.kill("SIGTERM");
  });

/** Окружение operator.mjs без переменных Платформы: всё — из EnvironmentFile. */
const bareEnv = (): NodeJS.ProcessEnv => ({ PATH: process.env.PATH, HOME: process.env.HOME });

describe.skipIf(!DATABASE_URL)("приёмка песочницы на PostgreSQL: operator.mjs, runAcceptance против main.ts sandbox (SANDBOX-ACC К2.1)", () => {
  const schema = `t_${process.pid}_${Date.now()}_acc`;
  const dir = mkdtempSync(join(tmpdir(), "acc-"));
  const caPath = join(dir, "sandbox-ca");
  const paramsPath = join(dir, "params.json");
  const envFile = join(dir, "env");
  let admin: pg.Pool;
  let pool: pg.Pool;
  let url: string;
  let fingerprint: string;
  let caPem: string;
  /** Весь вывод operator.mjs за файл — для проверки утечек. */
  let transcript = "";
  const children: ChildProcess[] = [];

  /** Переменные сервиса — значения, которые systemd передал бы из EnvironmentFile. */
  const serviceEnv = (port: number): NodeJS.ProcessEnv => {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PLATFORM_ENV: "sandbox",
      HOST: "127.0.0.1",
      PORT: String(port),
      PLATFORM_TLS_HOSTNAMES: "localhost,127.0.0.1",
      DATABASE_URL: url,
      PLATFORM_CA_KEY_PATH: caPath,
      PARAMS_PATH: paramsPath,
    };
    for (const k of ["PAO_TRUSTED_PROXIES", "PARTICIPANT_KEYS_PATH"]) delete env[k];
    return env;
  };

  /** operator.mjs локально, как на VPS: node <программа> <корень> <EnvironmentFile>, запрос — в stdin. */
  const operator = async (step: string, request: Record<string, unknown>, file = envFile) => {
    const r = await spawnExec(process.execPath, [OPERATOR_PROGRAM, ROOT, file], JSON.stringify(request), bareEnv());
    transcript += `${r.stdout}\n${r.stderr}\n`;
    return { raw: r, reply: () => parseReply(step, r) };
  };

  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    const u = new URL(DATABASE_URL as string);
    u.searchParams.set("options", `-c search_path=${schema}`);
    url = u.toString();
    pool = new pg.Pool({ connectionString: url, max: 2 });
    // Схема размечена до operator.mjs, как на VPS: миграции применяет сервис при запуске, программа допуска их не применяет.
    await applyPlatformMigrations(pool);

    const params = loadParams();
    writeFileSync(paramsPath, JSON.stringify({ ...JSON.parse(readFileSync(join(ROOT, "config/params.stand.json"), "utf8")), agent_cert_ttl_days: TTL_DAYS }));
    const ca = initCaFile(caPath, { now: new Date(Date.now() - 60_000), ttlDays: params.sandbox_ca_ttl_days });
    fingerprint = ca.fingerprint;
    caPem = ca.certificatePem;
    // EnvironmentFile unit: комментарии, кавычки двойные и одинарные, пустые строки (docs/deploy/sandbox.md §5).
    writeFileSync(
      envFile,
      [
        "# песочница Платформы",
        'PLATFORM_ENV="sandbox"',
        "HOST=127.0.0.1",
        "",
        `DATABASE_URL='${url}'`,
        `PLATFORM_CA_KEY_PATH="${caPath}"`,
        "# PARAMS_PATH — абсолютный",
        `PARAMS_PATH=${paramsPath}`,
        'PAO_TRUSTED_PROXIES=""',
        "",
      ].join("\n"),
    );
    chmodSync(envFile, 0o600);
  });
  afterAll(async () => {
    for (const c of children) await stop(c);
    await pool?.end();
    await admin?.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin?.end();
  });

  it("operator.mjs: допуск с CSR — сертификат, operator = op-acceptance; без CSR — APPLICATION_INCOMPLETE; отзыв — true, повтор — true, неизвестный — false", async () => {
    const code = `nspk:agent:accpg-${Date.now().toString(36)}:v1`;
    const csr = newCsr();
    const d = (await operator("admit", { cmd: "admit", application: { ...buyerApplication(code, newAgentSide()), csr: csr.csr } })).reply();
    expect(d).toMatchObject({ admitted: true, agent_code: code });
    const certificate = d.certificate as { serial: string; der: string; not_after: string };
    expect(certificate.serial).toMatch(/^[0-9a-f]+$/);
    // Срок — из PARAMS_PATH файла (7 дней), а не из стендовых параметров (90).
    const days = (Date.parse(certificate.not_after) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(TTL_DAYS - 1);
    expect(days).toBeLessThan(TTL_DAYS + 1);
    const row = await pool.query<{ operator: string; contour: string }>("SELECT operator, contour FROM agents WHERE agent_code = $1", [code]);
    expect(row.rows).toEqual([{ operator: "op-acceptance", contour: "sandbox" }]);

    const noCsr = (await operator("admit", { cmd: "admit", application: buyerApplication(`nspk:agent:accpg-n${Date.now().toString(36)}:v1`, newAgentSide()) })).reply();
    expect(noCsr).toMatchObject({ admitted: false });
    expect(noCsr.reasons).toContain("APPLICATION_INCOMPLETE");

    expect((await operator("revoke", { cmd: "revoke", serial: certificate.serial })).reply()).toEqual({ revoked: true });
    expect((await operator("revoke", { cmd: "revoke", serial: certificate.serial })).reply()).toEqual({ revoked: true });
    expect((await operator("revoke", { cmd: "revoke", serial: randomBytes(16).toString("hex") })).reply()).toEqual({ revoked: false });
  }, 60_000);

  it("operator.mjs: неверный DATABASE_URL и испорченный файл УЦ — только код, без пароля, хоста, пути и текста исключения", async () => {
    const password = `leak-${randomBytes(6).toString("hex")}`;
    const badHost = "acc-nohost-7f3a.invalid";
    const application = { ...buyerApplication(`nspk:agent:accpg-b${Date.now().toString(36)}:v1`, newAgentSide()), csr: newCsr().csr };

    const badDb = join(dir, "env-bad-db");
    writeFileSync(badDb, `PLATFORM_ENV=sandbox\nDATABASE_URL=postgres://agentic:${password}@${badHost}:5432/x\nPLATFORM_CA_KEY_PATH=${caPath}\nPARAMS_PATH=${paramsPath}\n`);
    const brokenCa = join(dir, "ca-broken");
    writeFileSync(brokenCa, "испорченный файл УЦ\n", { mode: 0o600 });
    const badCa = join(dir, "env-bad-ca");
    writeFileSync(badCa, `PLATFORM_ENV=sandbox\nDATABASE_URL=${url}\nPLATFORM_CA_KEY_PATH=${brokenCa}\nPARAMS_PATH=${paramsPath}\n`);

    for (const file of [badDb, badCa]) {
      const { raw } = await operator("admit", { cmd: "admit", application }, file);
      expect(raw.code).toBe(1);
      expect(raw.stdout.trim()).toMatch(/^\{"error":"[A-Za-z0-9_]+"\}$/);
      const all = `${raw.stdout}${raw.stderr}`;
      for (const secret of [password, badHost, brokenCa, dir, "испорченный"]) expect(all).not.toContain(secret);
      expect(all).not.toMatch(/Error|\n\s+at /);
    }
  }, 60_000);

  it("runAcceptance против процесса main.ts sandbox на PG — 16 из 16: сертификат от operator.mjs принят ступенью 0, перезапуск — новый сертификат сервера", async () => {
    const port = await freePort();
    let out = "";
    const start = () => {
      out = "";
      const proc = spawn(process.execPath, ["--import", "tsx", "src/main.ts"], { env: serviceEnv(port), stdio: ["ignore", "pipe", "pipe"] });
      proc.stdout?.on("data", (d: Buffer) => (out += d.toString("utf8")));
      proc.stderr?.on("data", (d: Buffer) => (out += d.toString("utf8")));
      children.push(proc);
      return proc;
    };
    let proc = start();

    // Порт оператора на этой машине: допуск и отзыв — operator.mjs, журнал — вывод текущего процесса, перезапуск — новый процесс.
    const op: OperatorPort = {
      admit: async (application) => (await operator("admit", { cmd: "admit", application })).reply() as never,
      revoke: async (serial) => (await operator("revoke", { cmd: "revoke", serial })).reply().revoked === true,
      journal: async () => out,
      restart: async () => {
        expect(await stop(proc)).toBe(0);
        proc = start();
      },
      close: async () => {},
    };

    // Готовность — процесс жив и порт принимает соединения; сертификат по корню смотрит проверка 1.
    const deadline = Date.now() + 60_000;
    for (;;) {
      expect(proc.exitCode, out).toBeNull();
      const up = await fetch(`https://127.0.0.1:${port}/health`).then(
        () => true,
        (e: { cause?: { code?: string } }) => e.cause?.code !== "ECONNREFUSED",
      );
      if (up || Date.now() > deadline) break;
      await new Promise((r) => setTimeout(r, 200));
    }

    const rs = await runAcceptance({ host: "127.0.0.1", port, caPem, fingerprint }, op, { readyTimeoutMs: 60_000 });
    const table = report(rs);
    transcript += table;
    expect(rs.map((r) => r.id)).toEqual([...CHECK_IDS]);
    expect(rs.filter((r) => !r.ok), table).toEqual([]);
    expect(accepted(rs), table).toBe(true);
    // Проверка 7 — сертификат, выданный operator.mjs, принят ступенью 0 процесса; 13.1 — сертификат сервера новый.
    const r = Object.fromEntries(rs.map((x) => [x.id, x]));
    expect(r["7"]?.actual).toMatch(/^допущен, серийный [0-9a-f]+; 200, agent_code свой$/);
    expect(r["13.1"]?.actual).toMatch(/сертификат новый$/);

    expect(await stop(proc)).toBe(0);
  }, 180_000);

  it("sshOperator через настоящий sh -c без ssh: mktemp, копия, запуск, удаление; после close() каталога нет", async () => {
    const dirs: string[] = [];
    // Как ssh: удалённая строка уходит в оболочку целиком; sudo -n -u <пользователь> снят — пользователь тот же.
    const exec: Exec = async (cmd, args, input) => {
      expect(cmd).toBe("ssh");
      const remote = (args[args.length - 1] as string).replace(/^sudo -n -u agentic /, "");
      const r = await spawnExec("sh", ["-c", remote], input, bareEnv());
      if (remote === "mktemp -d") dirs.push(r.stdout.trim());
      transcript += `${r.stdout}\n${r.stderr}\n`;
      return r;
    };
    const op = sshOperator({ target: "owner@vps.example", root: ROOT, envFile, unit: "agentic-platform", user: "agentic", exec });
    const code = `nspk:agent:accsh-${Date.now().toString(36)}:v1`;
    const d = await op.admit({ ...buyerApplication(code, newAgentSide()), csr: newCsr().csr });
    expect(d).toMatchObject({ admitted: true, agent_code: code });
    expect(await op.revoke(d.certificate?.serial as string)).toBe(true);
    expect(dirs).toHaveLength(1);
    expect(readFileSync(join(dirs[0] as string, "operator.mjs"), "utf8")).toBe(readFileSync(OPERATOR_PROGRAM, "utf8"));
    await op.close();
    expect(existsSync(dirs[0] as string)).toBe(false);
  }, 60_000);

  it("утечки: в выводе operator.mjs и таблице нет закрытых ключей, строки подключения и пароля", () => {
    expect(transcript).not.toBe("");
    expect(transcript).not.toContain("PRIVATE KEY");
    expect(transcript).not.toContain(url);
    const password = new URL(url).password;
    if (password) expect(transcript).not.toContain(`:${password}@`);
    expect(transcript).not.toMatch(/\n\s+at /);
  });
});
