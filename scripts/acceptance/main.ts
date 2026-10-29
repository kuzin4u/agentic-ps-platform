// npm run acceptance (SANDBOX-ACC, решение владельца 28.10): приёмка развёрнутой песочницы с Mac владельца. Сеть — по
// TLS к адресу и порту; допуск, отзыв, журнал и перезапуск — порт оператора по ssh (docs/deploy/sandbox.md).
// Выход: 0 — принято, 1 — не принято, 2 — ошибка параметров.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { accepted, normFingerprint, report, runAcceptance } from "./checks.js";
import { OperatorError, sshOperator } from "./operator.js";

const USAGE = `npm run acceptance -- --host <адрес> --port <порт> --ca <корень PEM> --fingerprint <SHA-256> --ssh <user@vps>
  [--root /opt/agentic-ps-platform] [--env-file /etc/agentic-platform/env] [--unit agentic-platform] [--user agentic]`;

const usage = (why: string): never => {
  console.error(`acceptance: ${why}\n${USAGE}`);
  process.exit(2);
};

const parse = () => {
  try {
    return parseArgs({
      options: {
        host: { type: "string" },
        port: { type: "string" },
        ca: { type: "string" },
        fingerprint: { type: "string" },
        ssh: { type: "string" },
        root: { type: "string", default: "/opt/agentic-ps-platform" },
        "env-file": { type: "string", default: "/etc/agentic-platform/env" },
        unit: { type: "string", default: "agentic-platform" },
        user: { type: "string", default: "agentic" },
      },
      strict: true,
    }).values;
  } catch (e) {
    return usage(e instanceof Error ? e.message : "неверные параметры");
  }
};
const values = parse();

const { host, ca, fingerprint, ssh } = values;
const port = Number(values.port);
if (!host || !ca || !fingerprint || !ssh) usage("нужны --host, --port, --ca, --fingerprint, --ssh");
if (!Number.isInteger(port) || port < 1 || port > 65535) usage(`недопустимый --port ${values.port}`);
if (!/^[0-9a-f]{64}$/.test(normFingerprint(fingerprint as string))) usage("--fingerprint — SHA-256, 64 hex (двоеточия допустимы)");
let caPem = "";
try {
  caPem = readFileSync(ca as string, "utf8");
} catch (e) {
  usage(`корень не прочитан: ${(e as NodeJS.ErrnoException).code ?? "ошибка"}`);
}

let op;
try {
  op = sshOperator({
    target: ssh as string,
    root: values.root as string,
    envFile: values["env-file"] as string,
    unit: values.unit as string,
    user: values.user as string,
  });
} catch (e) {
  usage(e instanceof OperatorError ? e.code : "неверные параметры ssh");
}

const results = await runAcceptance({ host: host as string, port, caPem, fingerprint: fingerprint as string }, op as NonNullable<typeof op>);
console.log(report(results));
process.exit(accepted(results) ? 0 : 1);
