// Каталог ключей агентов для продавцов и площадок — JWKS (RFC 7517), ключ — JWK по RFC 8037 (РП22 п. 1).
// kid — тот же отпечаток RFC 7638, что в реестре и в Key.kid ПАО: он вычисляется из {crv, kty, x}.
// Частные члены agent_code, nbf, exp сторонние библиотеки игнорируют — их проверяет продавец сам (CO-4).
import { ED25519, type AgentKey } from "./keys.js";

export interface AgentJwk {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: string;
  readonly alg: "EdDSA";
  readonly use: "sig";
  readonly kid: string;
  /** Код агента, которому принадлежит ключ: продавец сверяет его с x-agent-code обращения (инвариант 5). */
  readonly agent_code: string;
  /** Срок ключа, секунды Unix: nbf = valid_from, exp = valid_to (РП23 п. 4). */
  readonly nbf: number;
  readonly exp: number;
}

export interface AgentJwks {
  readonly keys: readonly AgentJwk[];
}

const unix = (iso: string): number => Math.floor(Date.parse(iso) / 1000);

/** Ключ реестра в виде JWK каталога; ключ не Ed25519 (точка расширения РП5) — null: RFC 8037 его не описывает. */
export function agentJwk(key: AgentKey): AgentJwk | null {
  if (key.alg !== ED25519.alg) return null;
  const jwk = ED25519.toJwk(key.public_key);
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
  return Object.freeze({
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x,
    alg: "EdDSA",
    use: "sig",
    kid: key.kid,
    agent_code: key.agent_code,
    nbf: unix(key.valid_from),
    exp: unix(key.valid_to),
  });
}
