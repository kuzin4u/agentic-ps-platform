// Проверка подписи агента продавцом по каталогу ключей агентов (РП22 п. 1–3, A5 п. 2.2).
// Продавец не знает модели статусов реестра: в каталоге только действующие ключи, неизвестный kid — отказ.
// Подпись проверяет agentic-core verifyRequest — тот же код, что у Платформы и агента.
import { createPublicKey } from "node:crypto";
import { ed25519Verifier, verifyRequest, type HttpLike } from "@kuzin4u/agentic-core";
import type { AgentJwk, AgentJwks } from "../../registry/jwks.js";

export type MerchantAuthError =
  /** kid нет в каталоге и после перечитывания (или перечитывание в окне уже было). */
  | "KEY_UNKNOWN"
  /** agent_code ключа ≠ x-agent-code: агент A подписал за агента B (инвариант 5). */
  | "AGENT_MISMATCH"
  /** Срок ключа по nbf / exp не наступил или истёк. */
  | "KEY_EXPIRED"
  | "SIGNATURE_INVALID";

export type MerchantAuthResult =
  | { readonly ok: true; readonly agent_code: string; readonly kid: string }
  | { readonly ok: false; readonly code: MerchantAuthError };

export interface MerchantVerifierOptions {
  /** Срок кэша каталога (`merchant_jwks_max_age_sec`; значение — PS-30). */
  readonly maxAgeMs: number;
  /** Не чаще одного перечитывания по неизвестному kid за окно (`merchant_jwks_refetch_min_sec`, РП22 п. 3). */
  readonly refetchMinMs: number;
  readonly skewSec: number;
  readonly now?: () => Date;
}

const KEYID = /;keyid="([^"]+)"/;

/** Открытый ключ JWK в DER SPKI base64 — вход ed25519Verifier agentic-core. */
const spkiOf = (jwk: AgentJwk): string =>
  createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: "jwk" })
    .export({ type: "spki", format: "der" })
    .toString("base64");

/** Каталог ключей у продавца: кэш, перечитывание по сроку и по неизвестному kid с ограничением частоты. */
export class MerchantAgentVerifier {
  private readonly now: () => Date;
  #keys = new Map<string, AgentJwk>();
  #fetchedAt = Number.NEGATIVE_INFINITY;
  readonly #nonces = new Map<string, number>();
  /** Число чтений каталога — для тестов ограничения перечитывания. */
  fetches = 0;

  constructor(
    private readonly fetchJwks: () => AgentJwks | Promise<AgentJwks>,
    private readonly opts: MerchantVerifierOptions,
  ) {
    this.now = opts.now ?? (() => new Date());
  }

  /** Окно считается от попытки чтения: недоступный каталог не перечитывается на каждый запрос (РП22 п. 3). */
  private async refresh(nowMs: number): Promise<void> {
    this.#fetchedAt = nowMs;
    this.fetches++;
    try {
      const jwks = await this.fetchJwks();
      this.#keys = new Map(jwks.keys.map((k) => [k.kid, k]));
    } catch (e) {
      // Устаревшие ключи после неудачного чтения не используются: отказ, не догадка (инвариант 3).
      this.#keys = new Map();
      throw e;
    }
  }

  async verify(req: HttpLike): Promise<MerchantAuthResult> {
    const nowMs = this.now().getTime();
    const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), v]));
    const kid = KEYID.exec(headers["signature-input"] ?? "")?.[1];
    const agentCode = headers["x-agent-code"];
    if (!kid || !agentCode) return { ok: false, code: "SIGNATURE_INVALID" };

    if (nowMs - this.#fetchedAt >= this.opts.maxAgeMs) await this.refresh(nowMs);
    else if (!this.#keys.has(kid) && nowMs - this.#fetchedAt >= this.opts.refetchMinMs) await this.refresh(nowMs);
    const jwk = this.#keys.get(kid);
    if (!jwk) return { ok: false, code: "KEY_UNKNOWN" };
    if (jwk.agent_code !== agentCode) return { ok: false, code: "AGENT_MISMATCH" };
    if (nowMs < jwk.nbf * 1000 || nowMs >= jwk.exp * 1000) return { ok: false, code: "KEY_EXPIRED" };

    for (const [k, until] of this.#nonces) if (until < nowMs) this.#nonces.delete(k);
    const nonceKey = (n: string): string => `${agentCode}\u0000${n}`;
    const r = verifyRequest(
      { ...req, headers },
      (k) => (k === kid ? { alg: "ed25519", publicKey: spkiOf(jwk), status: "ACTIVE" } : undefined),
      {
        now: nowMs,
        skewSec: this.opts.skewSec,
        seenNonce: (n) => n === "" || this.#nonces.has(nonceKey(n)),
        verifier: ed25519Verifier,
      },
    );
    if (!r.ok) return { ok: false, code: "SIGNATURE_INVALID" };
    this.#nonces.set(nonceKey(headers["x-nonce"] ?? ""), nowMs + 2 * this.opts.skewSec * 1000);
    return { ok: true, agent_code: agentCode, kid };
  }
}
