// npm run participant (Р-1031, Р-1040, сессия 61): тестовый банк-участник песочницы с Mac владельца.
// keygen — пара ed25519 и запись для participants.json; закрытый ключ — только на Mac, вне клона репозитория.
// Выход: 0 — сделано, 1 — отказ, 2 — ошибка параметров.
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { keygen, ParticipantToolError, repoRootOf } from "./keys.js";

const USAGE = `npm run participant -- keygen --code <participant_code> --key <путь к закрытому ключу вне клона>`;

const usage = (why: string): never => {
  console.error(`participant: ${why}\n${USAGE}`);
  process.exit(2);
};

const [command, ...rest] = process.argv.slice(2);
if (command !== "keygen") usage(`неизвестная команда «${command ?? ""}»`);

const parse = () => {
  try {
    return parseArgs({ args: rest, options: { code: { type: "string" }, key: { type: "string" } }, strict: true }).values;
  } catch (e) {
    return usage(e instanceof Error ? e.message : "неверные параметры");
  }
};
const values = parse();
if (!values.code || !values.key) usage("нужны --code и --key");

try {
  const repoRoot = repoRootOf(dirname(fileURLToPath(import.meta.url)));
  const record = keygen({ participant_code: values.code as string, keyPath: values.key as string, repoRoot });
  // Только открытая запись: закрытый ключ остаётся в файле.
  console.log(JSON.stringify(record, null, 2));
  process.exit(0);
} catch (e) {
  if (e instanceof ParticipantToolError) {
    console.error(`participant: отказ ${e.message}`);
    process.exit(1);
  }
  throw e;
}
