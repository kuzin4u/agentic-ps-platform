// Тестовый банк-участник песочницы (Р-1031, Р-1040, сессия 61): ключ ed25519 банка и запись для participants.json.
// Закрытый ключ — только на Mac владельца: PKCS8 PEM, 0600, без перезаписи, не внутри клона репозитория (сверка с корнем
// git). Запись проверяется тем же конструктором, что и в рабочем сервере (stand: false), до записи ключа на диск.
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { closeSync, fchmodSync, openSync, realpathSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { ED25519, parseKey } from "../../src/registry/keys.js";
import { TrustedParticipants, type TrustedParticipantKey } from "../../src/participants/trusted.js";

/** Причины отказа инструмента — закрытый перечень; текст для человека — в main.ts. */
export type ParticipantToolCode =
  | "CODE_INVALID"
  | "KEY_DIR_MISSING"
  | "KEY_PATH_IN_REPO"
  | "KEY_EXISTS"
  | "REPO_ROOT_UNKNOWN";

export class ParticipantToolError extends Error {
  constructor(readonly code: ParticipantToolCode, detail: string) {
    super(`${code}: ${detail}`);
  }
}

/** Порядок отзыва тестового банка (РП37): по образцу стенда `bank:<participant_code>:revocation:v1`. */
export const revocationOrderOf = (participant_code: string): string => `bank:${participant_code}:revocation:v1`;

/**
 * Запись для participants.json (РП36 доп. п. 7): ровно поля файла, роль не указывается (ISSUER по умолчанию). Проверка —
 * конструктором рабочего сервера: код эмулятора стенда, недопустимый код или порядок отзыва — отказ до записи ключа.
 */
export function participantRecord(participant_code: string, publicKey: KeyObject): TrustedParticipantKey {
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const parsed = parseKey([ED25519], "ed25519", public_key);
  if (!parsed) throw new ParticipantToolError("CODE_INVALID", "ключ ed25519 не разобран");
  const record: TrustedParticipantKey = {
    participant_code,
    kid: parsed.kid,
    alg: "ed25519",
    public_key,
    revocation_order: revocationOrderOf(participant_code),
  };
  try {
    new TrustedParticipants([record], { stand: false });
  } catch (e) {
    throw new ParticipantToolError("CODE_INVALID", (e as Error).message);
  }
  return record;
}

const inside = (root: string, p: string): boolean => {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
};

/**
 * Путь ключа вне клона (Р-1040): каталог должен существовать; сравнение — по реальным путям (символьные ссылки и
 * /tmp → /private/tmp на macOS), иначе ссылка из внешнего каталога в клон прошла бы сверку.
 */
export function keyPathOutside(keyPath: string, repoRoot: string): string {
  const abs = resolve(keyPath);
  let dir: string;
  try {
    dir = realpathSync(dirname(abs));
  } catch {
    throw new ParticipantToolError("KEY_DIR_MISSING", `каталог ${dirname(abs)} не существует`);
  }
  const target = join(dir, basename(abs));
  if (inside(realpathSync(repoRoot), target)) {
    throw new ParticipantToolError("KEY_PATH_IN_REPO", `путь ${target} внутри клона ${repoRoot}`);
  }
  return target;
}

/** Корень git каталога инструмента; не определён — отказ (fail-closed), а не запись куда угодно. */
export function repoRootOf(dir: string): string {
  try {
    const out = execFileSync("git", ["-C", dir, "rev-parse", "--show-toplevel"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    if (out === "") throw new Error("пусто");
    return out;
  } catch {
    throw new ParticipantToolError("REPO_ROOT_UNKNOWN", `корень git для ${dir} не определён`);
  }
}

/** Закрытый ключ — PKCS8 PEM, создание без перезаписи (O_EXCL) и 0600 явно (umask только снимает биты). */
export function writePrivateKey(path: string, privateKey: KeyObject): void {
  let fd: number;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new ParticipantToolError("KEY_EXISTS", `${path} уже есть — перезаписи нет`);
    throw e;
  }
  try {
    fchmodSync(fd, 0o600);
    writeSync(fd, privateKey.export({ type: "pkcs8", format: "pem" }) as string);
  } finally {
    closeSync(fd);
  }
}

/** keygen: пара → запись (проверена) → путь (вне клона) → ключ на диск; в выводе закрытого ключа нет. */
export function keygen(opts: { readonly participant_code: string; readonly keyPath: string; readonly repoRoot: string }): TrustedParticipantKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const record = participantRecord(opts.participant_code, publicKey);
  const target = keyPathOutside(opts.keyPath, opts.repoRoot);
  writePrivateKey(target, privateKey);
  return record;
}
