// Ключи агентов (A2 п. 5, РП23): разбор открытого ключа, kid — отпечаток JWK по RFC 7638, срок и статус.
// Закрытый ключ агента Платформа не получает: пару генерирует оператор агента (РП23 п. 2).
import { createHash, createPublicKey } from "node:crypto";
import type { Params } from "../shared/config.js";
import type { Key } from "../shared/pao.js";
import type { Contour } from "./model.js";

/** Статусы ключа — перечень Key.status ПАО. */
export const KEY_STATUSES = ["ACTIVE", "REVOKED", "EXPIRED"] as const;
export type KeyStatus = (typeof KEY_STATUSES)[number];

/** Сроки ключей из стендовых параметров (PARAMS.md, A2 п. 5.3). */
export type KeyPolicy = Pick<Params, "key_ttl_days" | "key_overlap_days">;

/** Обязательные члены JWK открытого ключа (RFC 7638 §3.2) — вход отпечатка. */
export type JwkMembers = Readonly<Record<string, string>>;

/**
 * Алгоритм ключа — точка расширения РП5: разбор `public_key` (DER SPKI, base64) в обязательные члены JWK.
 * Ключ не разбирается или не того алгоритма — null.
 */
export interface KeyAlgorithm {
  readonly alg: string;
  toJwk(public_key: string): JwkMembers | null;
}

/**
 * Строгий разбор base64 SPKI: только каноническая запись (RFC 4648 §3.5; РП23, дополнение 6), иначе один ключ
 * получил бы несколько строк. Запись должна совпасть с повторным кодированием своих байтов: так отсекаются
 * лишние биты перед «=», запись без дополнения, пробелы, переводы строки и алфавит base64url.
 */
function spki(public_key: string): ReturnType<typeof createPublicKey> | null {
  const der = Buffer.from(public_key, "base64");
  if (der.length === 0 || der.toString("base64") !== public_key) return null;
  try {
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    return key.export({ type: "spki", format: "der" }).equals(der) ? key : null;
  } catch {
    return null;
  }
}

// Кривая Ed25519 (RFC 8032 §5.1): p = 2^255 − 19, d = −121665/121666, a = −1.
const P = 2n ** 255n - 19n;
const mod = (n: bigint): bigint => ((n % P) + P) % P;
function pow(b: bigint, e: bigint): bigint {
  let r = 1n;
  for (b = mod(b); e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) r = (r * b) % P;
  return r;
}
const inv = (n: bigint): bigint => pow(n, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

type Point = readonly [bigint, bigint];

/** Полная формула сложения скрученной кривой Эдвардса (a = −1). */
function add([x1, y1]: Point, [x2, y2]: Point): Point {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + y1 * x2) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
}

/** Разбор 32 байт по RFC 8032 §5.1.3 со строгой каноничностью: y < p, x = 0 без знакового бита. Иначе null. */
function decodePoint(bytes: Buffer): Point | null {
  if (bytes.length !== 32) return null;
  const sign = bytes[31]! >> 7;
  const le = Buffer.from(bytes);
  le[31] = le[31]! & 0x7f;
  const y = BigInt(`0x${Buffer.from(le).reverse().toString("hex")}`);
  if (y >= P) return null;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  if (mod(v * x * x) !== u) {
    if (mod(v * x * x) !== mod(-u)) return null;
    x = mod(x * SQRT_M1);
  }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = mod(-x);
  return [x, y];
}

/**
 * Слабый открытый ключ Ed25519 (аудит PS-04 №1): неканоническая запись или точка малого порядка ([8]A = O).
 * С ключом малого порядка подпись «R = нейтраль, S = 0» проходит для любого сообщения — подписать может любой (A2 п. 5.1).
 */
export function isWeakEd25519(x: Buffer): boolean {
  const a = decodePoint(x);
  if (!a) return true;
  let q: Point = a;
  for (let i = 0; i < 3; i++) q = add(q, q);
  return q[0] === 0n && q[1] === 1n;
}

export const ED25519: KeyAlgorithm = {
  alg: "ed25519",
  toJwk(public_key) {
    const key = spki(public_key);
    if (!key || key.asymmetricKeyType !== "ed25519") return null;
    // DER SPKI Ed25519: 12 байт заголовка + 32 байта точки (RFC 8410); заголовок проверен разбором и повторным экспортом.
    if (isWeakEd25519(Buffer.from(public_key, "base64").subarray(12))) return null;
    const { crv, kty, x } = key.export({ format: "jwk" });
    return typeof crv === "string" && typeof kty === "string" && typeof x === "string" ? { crv, kty, x } : null;
  },
};

/** Алгоритмы по контуру (РП23 п. 2): песочница — ed25519; контур оператора — ГОСТ после точки расширения РП5, до неё пусто. */
export const DEFAULT_KEY_ALGORITHMS: Readonly<Record<Contour, readonly KeyAlgorithm[]>> = Object.freeze({
  sandbox: Object.freeze([ED25519]),
  operator: Object.freeze([]),
});

/** Отпечаток JWK по RFC 7638: члены по возрастанию имён, JSON без пробелов, SHA-256, base64url без дополнения. */
export function jwkThumbprint(jwk: JwkMembers): string {
  const canonical = `{${Object.keys(jwk)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${JSON.stringify(jwk[k])}`)
    .join(",")}}`;
  return createHash("sha256").update(canonical, "utf8").digest("base64url");
}

export interface ParsedKey {
  readonly kid: string;
  readonly alg: string;
  readonly public_key: string;
}

/** Ключ из заявления или запроса: `alg` из перечня контура и разбираемый `public_key`; иначе null (KEY_INVALID). */
export function parseKey(
  algorithms: readonly KeyAlgorithm[],
  alg: unknown,
  public_key: unknown,
): ParsedKey | null {
  if (typeof alg !== "string" || typeof public_key !== "string") return null;
  const a = algorithms.find((x) => x.alg === alg);
  const jwk = a?.toJwk(public_key);
  return jwk ? { kid: jwkThumbprint(jwk), alg, public_key } : null;
}

export interface AgentKey {
  readonly kid: string;
  readonly agent_code: string;
  readonly alg: string;
  readonly public_key: string;
  readonly valid_from: string;
  readonly valid_to: string;
  /** Момент отзыва; отзыв необратим (РП23 п. 5). */
  readonly revoked_at: string | null;
  readonly row_version: number;
}

const DAY_MS = 86_400_000;

export function newAgentKey(agent_code: string, parsed: ParsedKey, now: Date, policy: KeyPolicy): AgentKey {
  return {
    kid: parsed.kid,
    agent_code,
    alg: parsed.alg,
    public_key: parsed.public_key,
    valid_from: now.toISOString(),
    valid_to: new Date(now.getTime() + policy.key_ttl_days * DAY_MS).toISOString(),
    revoked_at: null,
    row_version: 1,
  };
}

/** Срок, до которого действует ключ после регистрации нового: не дольше перекрытия (РП23 п. 4). */
export const overlapEnd = (now: Date, policy: KeyPolicy): number => now.getTime() + policy.key_overlap_days * DAY_MS;

/** Статус на момент now: отозван — REVOKED; наступил valid_to — EXPIRED (РП23 п. 4). */
export function keyStatus(key: AgentKey, now: Date): KeyStatus {
  if (key.revoked_at !== null) return "REVOKED";
  return now.getTime() >= Date.parse(key.valid_to) ? "EXPIRED" : "ACTIVE";
}

/** Ключ в виде схемы Key ПАО. */
export const toPaoKey = (key: AgentKey, now: Date): Key => ({
  kid: key.kid,
  alg: key.alg,
  public_key: key.public_key,
  valid_from: key.valid_from,
  valid_to: key.valid_to,
  status: keyStatus(key, now),
});

// Сборка падает, если перечень статусов разойдётся с ПАО.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
export const KEY_STATUSES_MATCH_PAO: Same<KeyStatus, Key["status"]> = true;
