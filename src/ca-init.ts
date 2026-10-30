// Инициализация УЦ песочницы (РП66 п. 6; решения владельца 28.10, PR #80): `npm run ca:init`. Путь — только из
// PLATFORM_CA_KEY_PATH (без аргумента); срок — sandbox_ca_ttl_days; существующий файл не перезаписывается. Вывод —
// путь, отпечаток SHA-256 и открытый корневой сертификат PEM (агент сверяет отпечаток при настройке); закрытого ключа нет.
import { initCaFile } from "./registry/index.js";
import { loadParams } from "./shared/config.js";

const path = process.env.PLATFORM_CA_KEY_PATH;
if (path === undefined || path === "") {
  console.error("ca:init: PLATFORM_CA_KEY_PATH не задан");
  process.exit(1);
}
try {
  // Корень — с тем же запасом notBefore, что у сертификатов агента и сервера (РП66 нюанс Р-918).
  const params = loadParams();
  const ca = initCaFile(path, { now: new Date(), ttlDays: params.sandbox_ca_ttl_days, backdateSec: params.cert_not_before_backdate_sec });
  console.log(`ca:init: УЦ песочницы создан: ${path} (0600)`);
  console.log(`ca:init: отпечаток SHA-256 корневого сертификата: ${ca.fingerprint}`);
  console.log(`ca:init: срок: ${ca.notBefore.toISOString()} — ${ca.notAfter.toISOString()}`);
  process.stdout.write(ca.certificatePem);
} catch (err) {
  // Только код ошибки файловой системы (EEXIST — файл уже есть, не перезаписан) или класс: ключа в тексте нет и быть не может.
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  console.error(`ca:init: УЦ не создан: ${code ?? (err instanceof Error ? err.name : typeof err)}${code === "EEXIST" ? " — файл уже есть, не перезаписан" : ""}`);
  process.exit(1);
}
