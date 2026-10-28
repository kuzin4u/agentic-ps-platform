// П1 Ключ УЦ песочницы — файл с явной инициализацией (РП66 п. 6, уточняет РП65 п. 4): файл PLATFORM_CA_KEY_PATH создаёт
// только `npm run ca:init` (PKCS#8 и корневой сертификат одним PEM, 0600, без перезаписи); при запуске sandbox файл
// только читается. Неверно смонтированный том не создаёт молча новый УЦ — выданные сертификаты перестали бы проверяться.
import { closeSync, constants, fchmodSync, fstatSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { SandboxCa, type SandboxCaOptions } from "./ca.js";

/** Виды причины STARTUP_CA_KEY_INVALID (РП66 п. 6) — закрытый перечень, только в журнал процесса. */
export const CA_KEY_REASONS = ["NO_PATH", "NO_FILE", "MODE_TOO_OPEN", "UNPARSABLE", "KEY_MISMATCH", "OUTSIDE_VALIDITY"] as const;
export type CaKeyReason = (typeof CA_KEY_REASONS)[number];

/** Отказ загрузки ключа УЦ: текст — только вид причины, без пути и содержимого файла. */
export class CaKeyError extends Error {
  constructor(readonly reason: CaKeyReason) {
    super(`ключ УЦ песочницы: ${reason}`);
    this.name = "CaKeyError";
  }
}

/** Права файла ключа — не шире 0600: группе, прочим и на исполнение — ничего. */
const MODE_ALLOWED = 0o600;

/**
 * Ключ УЦ при запуске sandbox: пути нет — NO_PATH; файла нет, не читается или не обычный файл — NO_FILE; права шире 0600 —
 * MODE_TOO_OPEN; дальше — вид причины SandboxCa.load. Права и содержимое — с одного дескриптора (без гонки «проверил — подменили»).
 */
export function loadCaFile(path: string | undefined, now: Date): SandboxCa {
  if (path === undefined || path === "") throw new CaKeyError("NO_PATH");
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    throw new CaKeyError("NO_FILE");
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new CaKeyError("NO_FILE");
    if ((st.mode & 0o777 & ~MODE_ALLOWED) !== 0) throw new CaKeyError("MODE_TOO_OPEN");
    const loaded = SandboxCa.load(readFileSync(fd, "utf8"), now);
    if (!loaded.ok) throw new CaKeyError(loaded.reason);
    return loaded.ca;
  } finally {
    closeSync(fd);
  }
}

/**
 * Инициализация УЦ (`npm run ca:init`): новая пара и корневой сертификат — в новый файл, права 0600. Файл уже есть — EEXIST
 * из openSync, существующий не перезаписывается; сбой записи — созданный файл удаляется (полузаписанный УЦ не остаётся).
 */
export function initCaFile(path: string, opts: SandboxCaOptions): SandboxCa {
  const ca = SandboxCa.generate(opts);
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, MODE_ALLOWED);
  try {
    // Режим при создании урезается umask, но не расширяется; fchmod — явно 0600 при любой umask.
    fchmodSync(fd, MODE_ALLOWED);
    writeFileSync(fd, ca.exportPem());
  } catch (err) {
    closeSync(fd);
    unlinkSync(path);
    throw err;
  }
  closeSync(fd);
  return ca;
}
