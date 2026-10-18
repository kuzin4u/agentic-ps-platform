// П9 Подписка на события (РП40, PS-08 К1.3б): форма адреса и проверка адресов имени от SSRF. Платформа шлёт POST по адресу,
// который прислал агент, поэтому адрес проверяется при PUT и заново перед каждой отправкой (РП40 п. 2–4).
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import type { Event } from "../shared/pao.js";

export type { AgentSubscription } from "../registry/model.js";

/** Типы событий ПАО 1.4.0 — перечень Event.type; сборка падает, если разойдутся с типами ядра. */
export const EVENT_TYPES = [
  "mandate.signed",
  "mandate.rejected",
  "mandate.revoked",
  "mandate.exhausted",
  "confirmation.required",
  "confirmation.approved",
  "confirmation.rejected",
  "confirmation.expired",
  "operation.authorized",
  "operation.declined",
  "operation.settled",
  "operation.refunded",
  "agent.key_revoked",
  "agent.suspended",
  "agent.reinstated",
  "dispute.updated",
  "deal.funded",
  "deal.released",
  "deal.returned",
] as const;
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
export const EVENT_TYPES_MATCH_PAO: Same<(typeof EVENT_TYPES)[number], Event["type"]> = true;

/** Предел длины адреса подписки (РП40 п. 2). */
export const SUBSCRIPTION_URL_MAX = 2048;

/** Причина отказа адреса — только в журнал процесса; агенту — 400 REQUEST_INVALID (РП40 п. 2). */
export type SubscriptionUrlReason =
  | "url_invalid"
  | "scheme"
  | "port"
  | "userinfo"
  | "fragment"
  | "ip_literal"
  | "host_not_allowed"
  | "address_not_global"
  | "name_not_found"
  | "resolve_failed";

export type UrlCheck =
  | { readonly ok: true; readonly url: string; readonly host: string }
  | { readonly ok: false; readonly reason: SubscriptionUrlReason; readonly host?: string };

/**
 * Форма адреса (РП40 п. 2): https, порт не указан или 443, без userinfo и фрагмента, хост — имя DNS из списка
 * разрешённых (точное совпадение). Пустой список — отказ всем (fail-closed). Разрешение имени — отдельно (resolveGlobal).
 * Строка — как прислана: пробелы, управляющие символы и обратная косая черта — отказ до разбора, чтобы нормализация URL
 * (WHATWG) не превращала в допустимый адрес то, что агент не писал. Сохраняется нормализованный `href`.
 * При отказе после разбора — хост для журнала процесса (без пути: путь может нести секрет агента).
 */
export function checkSubscriptionUrl(raw: string, allowHosts: readonly string[]): UrlCheck {
  if (raw.length === 0 || raw.length > SUBSCRIPTION_URL_MAX) return { ok: false, reason: "url_invalid" };
  if (/[\s\\\u0000-\u001f\u007f-\u009f]/u.test(raw)) return { ok: false, reason: "url_invalid" };
  if (!/^https:\/\//i.test(raw)) return { ok: false, reason: "scheme" };
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, reason: "url_invalid" };
  }
  const host = u.hostname;
  const authority = raw.slice("https://".length).split(/[/?#]/, 1)[0] as string;
  if (u.protocol !== "https:") return { ok: false, reason: "scheme", host };
  if (u.username !== "" || u.password !== "" || authority.includes("@")) return { ok: false, reason: "userinfo", host };
  if (u.hash !== "" || raw.includes("#")) return { ok: false, reason: "fragment", host };
  // URL убирает порт 443 у https; любой другой указанный порт — отказ.
  if (u.port !== "") return { ok: false, reason: "port", host };
  if (host.startsWith("[") || isIP(host) !== 0 || /^[0-9.]+$/.test(host)) return { ok: false, reason: "ip_literal", host };
  if (!allowHosts.includes(host)) return { ok: false, reason: "host_not_allowed", host };
  return { ok: true, url: u.href, host };
}

/** Не глобальные IPv4 (РП40 п. 3 и дополнение): всё, что не глобальный одноадресный. */
const NOT_GLOBAL_V4 = (() => {
  const b = new BlockList();
  for (const [net, prefix] of [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ] as const) {
    b.addSubnet(net, prefix, "ipv4");
  }
  return b;
})();

const globalV4 = (ip: string): boolean => isIP(ip) === 4 && !NOT_GLOBAL_V4.check(ip, "ipv4");

/** IPv6 в 16 байт; запись не по форме или с зоной — undefined. Встроенный IPv4 в конце (`::ffff:1.2.3.4`) — разбирается. */
export function ipv6Bytes(ip: string): Uint8Array | undefined {
  if (isIP(ip) !== 6 || ip.includes("%")) return undefined;
  let text = ip.toLowerCase();
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (tail) {
    const o = tail[1]!.split(".").map(Number);
    const h = (x: number, y: number) => ((x << 8) | y).toString(16);
    text = text.slice(0, -tail[1]!.length) + `${h(o[0]!, o[1]!)}:${h(o[2]!, o[3]!)}`;
  }
  const halves = text.split("::");
  const groups = (part: string): string[] => (part === "" ? [] : part.split(":"));
  const head = groups(halves[0]!);
  const rest = halves.length === 2 ? groups(halves[1]!) : [];
  const fill = 8 - head.length - rest.length;
  const all = halves.length === 2 ? [...head, ...Array<string>(fill).fill("0"), ...rest] : head;
  if (all.length !== 8) return undefined;
  const out = new Uint8Array(16);
  all.forEach((g, i) => {
    const v = parseInt(g, 16);
    out[2 * i] = v >> 8;
    out[2 * i + 1] = v & 0xff;
  });
  return out;
}

const v4At = (b: Uint8Array, at: number): string => `${b[at]}.${b[at + 1]}.${b[at + 2]}.${b[at + 3]}`;
const startsWith = (b: Uint8Array, prefix: readonly number[]): boolean => prefix.every((x, i) => b[i] === x);

/**
 * Глобальный IPv6 (РП40 п. 3 и дополнение): только глобальный одноадресный 2000::/3 — без 2001::/23 (служебные IETF,
 * в т. ч. Teredo 2001::/32), 2001:db8::/32 и 3fff::/20 (документация); 6to4 2002::/16 — по встроенному IPv4.
 * Вне 2000::/3 — только IPv4-mapped ::ffff:0:0/96 и NAT64 64:ff9b::/96 по встроенному IPv4. Остальное (::/96, fc00::/7,
 * fe80::/10, fec0::/10, ff00::/8, 100::/64, 64:ff9b:1::/48 …) — не глобальный.
 */
function globalV6(b: Uint8Array): boolean {
  const zeros10 = b.subarray(0, 10).every((x) => x === 0);
  if (zeros10 && b[10] === 0xff && b[11] === 0xff) return globalV4(v4At(b, 12));
  if (startsWith(b, [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0])) return globalV4(v4At(b, 12));
  if ((b[0]! & 0xe0) !== 0x20) return false;
  if (b[0] === 0x20 && b[1] === 0x01 && b[2]! < 0x02) return false; // 2001::/23
  if (startsWith(b, [0x20, 0x01, 0x0d, 0xb8])) return false; // 2001:db8::/32
  if (b[0] === 0x3f && b[1] === 0xff && b[2]! < 0x10) return false; // 3fff::/20
  if (b[0] === 0x20 && b[1] === 0x02) return globalV4(v4At(b, 2)); // 6to4
  return true;
}

/** Глобальный одноадресный адрес; не адрес — false (fail-closed). */
export function isGlobalAddress(ip: string): boolean {
  if (isIP(ip) === 4) return globalV4(ip);
  const b = ipv6Bytes(ip);
  return b !== undefined && globalV6(b);
}

/** Метка стендового порта (РП40 п. 8): рабочий сервер такой порт не принимает — отказ запуска. */
export const STAND_PORT: unique symbol = Symbol("pao:stand-port");

/** Порт разрешения имени: все адреса имени. На стенде подменяется (РП40 п. 8), в тестах — подмена DNS. */
export type HostResolver = (host: string) => Promise<readonly string[]>;

/** Системное разрешение имени: все адреса обоих семейств, в порядке ответа. */
export const systemResolver: HostResolver = async (host) =>
  (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);

export type ResolveCheck =
  | { readonly ok: true; readonly addresses: readonly string[] }
  | { readonly ok: false; readonly reason: "address_not_global" | "name_not_found" | "resolve_failed" };

/** Ответ DNS «имени нет» или «адресов нет» — отказ самого адреса, а не временный сбой. */
const NAME_NOT_FOUND = new Set(["ENOTFOUND", "ENODATA"]);

/**
 * Разрешение имени и проверка всех адресов (РП40 п. 2, 4; дополнение п. 3): хоть один не глобальный — `address_not_global`;
 * имени или адресов нет — `name_not_found` (отказ адреса); иной сбой и таймаут — `resolve_failed` (временный сбой).
 * Все три — без соединения (fail-closed).
 */
export async function resolveGlobal(host: string, resolve: HostResolver): Promise<ResolveCheck> {
  let addresses: readonly string[];
  try {
    addresses = await resolve(host);
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    return { ok: false, reason: typeof code === "string" && NAME_NOT_FOUND.has(code) ? "name_not_found" : "resolve_failed" };
  }
  if (addresses.length === 0) return { ok: false, reason: "name_not_found" };
  if (!addresses.every(isGlobalAddress)) return { ok: false, reason: "address_not_global" };
  return { ok: true, addresses: [...addresses] };
}
