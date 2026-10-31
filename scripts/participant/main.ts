// npm run participant (Р-1031, Р-1040, сессия 61): тестовый банк-участник песочницы с Mac владельца.
// keygen — пара ed25519 и запись для participants.json; закрытый ключ — только на Mac, вне клона репозитория.
// sign / revoke — подпись и отзыв мандата по ПИ-8 по HTTPS с доверием только к корню УЦ песочницы.
// Выход: 0 — сделано (ПИ-8 ответил 200), 1 — отказ (инструмента или ПИ-8), 2 — ошибка параметров.
import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { loadBankKey, revokeMandate, signMandate, type Reply, type Target } from "./client.js";
import { keygen, ParticipantToolError, repoRootOf } from "./keys.js";

const USAGE = `npm run participant -- keygen --code <participant_code> --key <путь к закрытому ключу вне клона>
npm run participant -- sign --host <адрес> --port <порт> --ca <корень PEM> --fingerprint <SHA-256> --key <ключ> --code <participant_code>
  --mandate <mandate_id> --hash <Mandate.hash> [--decision SIGN|REJECT] [--signature-type simple|qualified|gov_id] [--token-consent]
npm run participant -- revoke --host <адрес> --port <порт> --ca <корень PEM> --fingerprint <SHA-256> --key <ключ> --code <participant_code>
  --mandate <mandate_id> --hash <Mandate.hash>`;

const usage = (why: string): never => {
  console.error(`participant: ${why}\n${USAGE}`);
  process.exit(2);
};

const [command, ...rest] = process.argv.slice(2);
if (command !== "keygen" && command !== "sign" && command !== "revoke") usage(`неизвестная команда «${command ?? ""}»`);

const OPTIONS = {
  code: { type: "string" },
  key: { type: "string" },
  host: { type: "string" },
  port: { type: "string" },
  ca: { type: "string" },
  fingerprint: { type: "string" },
  mandate: { type: "string" },
  hash: { type: "string" },
  decision: { type: "string", default: "SIGN" },
  "signature-type": { type: "string", default: "simple" },
  "token-consent": { type: "boolean", default: false },
} as const;

const parse = () => {
  try {
    return parseArgs({ args: rest, options: OPTIONS, strict: true }).values;
  } catch (e) {
    return usage(e instanceof Error ? e.message : "неверные параметры");
  }
};
const v = parse();
if (!v.code || !v.key) usage("нужны --code и --key");

const done = (r: Reply): never => {
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.status === 200 ? 0 : 1);
};

try {
  if (command === "keygen") {
    const repoRoot = repoRootOf(dirname(fileURLToPath(import.meta.url)));
    const record = keygen({ participant_code: v.code as string, keyPath: v.key as string, repoRoot });
    // Только открытая запись: закрытый ключ остаётся в файле.
    console.log(JSON.stringify(record, null, 2));
    process.exit(0);
  }
  const port = Number(v.port);
  if (!v.host || !v.ca || !v.fingerprint || !v.mandate || !v.hash) usage("нужны --host, --port, --ca, --fingerprint, --mandate, --hash");
  if (!Number.isInteger(port) || port < 1 || port > 65535) usage(`недопустимый --port ${String(v.port)}`);
  let caPem = "";
  try {
    caPem = readFileSync(v.ca as string, "utf8");
  } catch (e) {
    usage(`корень не прочитан: ${(e as NodeJS.ErrnoException).code ?? "ошибка"}`);
  }
  const target: Target = { host: v.host as string, port, caPem, fingerprint: v.fingerprint as string };
  const key = loadBankKey(v.key as string, v.code as string);
  if (command === "sign") {
    const decision = v.decision as string;
    const signature_type = v["signature-type"] as string;
    if (decision !== "SIGN" && decision !== "REJECT") usage("--decision — SIGN или REJECT");
    if (signature_type !== "simple" && signature_type !== "qualified" && signature_type !== "gov_id") usage("--signature-type — simple, qualified или gov_id");
    done(
      await signMandate(target, key, {
        mandate_id: v.mandate as string,
        mandate_hash: v.hash as string,
        decision: decision as "SIGN" | "REJECT",
        signature_type: signature_type as "simple" | "qualified" | "gov_id",
        token_consent: v["token-consent"] === true,
      }),
    );
  }
  done(await revokeMandate(target, key, { mandate_id: v.mandate as string, mandate_hash: v.hash as string }));
} catch (e) {
  if (e instanceof ParticipantToolError) {
    console.error(`participant: отказ ${e.message}`);
    process.exit(1);
  }
  throw e;
}
