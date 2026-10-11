// П9 Проверка обращения ПАО (ПАО §2, A2 п. 5, РП23 п. 6): агент в реестре → подпись → статус агента.
// Подпись проверяет agentic-core verifyRequest — тот же код, которым подписывает агент (совместный тест С0).
// Ключ ищется только среди ключей агента из x-agent-code: иначе агент A подписывал бы за агента B (инвариант 5).
import { ed25519Verifier, verifyRequest, type Verifier } from "@kuzin4u/agentic-core";
import type { KeyForVerify } from "../registry/agent-keys.js";
import type { AgentRecord } from "../registry/model.js";

/** Обращение в том виде, в каком оно пришло: путь и запрос — без декодирования, тело — строкой, без тела — "" (РП16). */
export interface PaoRequest {
  readonly method: string;
  readonly path: string;
  readonly query: string;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly body: string;
}

export type PaoAuthError = "AGENT_UNKNOWN" | "SIGNATURE_INVALID" | "AGENT_KEY_REVOKED" | "AGENT_SUSPENDED";

export type PaoAuthResult =
  | { readonly ok: true; readonly agent: AgentRecord; readonly kid: string }
  | { readonly ok: false; readonly code: PaoAuthError; readonly norm: string };

/** Реестр и ключи в той мере, в какой они нужны проверке (П1). */
export interface PaoAuthSources {
  getAgent(agent_code: string): AgentRecord | undefined;
  lookupKey(agent_code: string, kid: string): KeyForVerify | undefined;
}

/**
 * Использованные nonce в паре «агент + nonce» (ПАО §2: не повторяется в пределах окна).
 * Хранятся ttlMs после запоминания; ttlMs ≥ 2 × signature_skew_sec (РП23 п. 6).
 */
export class NonceStore {
  readonly #until = new Map<string, number>();

  constructor(private readonly ttlMs: number) {}

  has(agent_code: string, nonce: string, nowMs: number): boolean {
    const until = this.#until.get(`${agent_code}\u0000${nonce}`);
    return until !== undefined && until > nowMs;
  }

  remember(agent_code: string, nonce: string, nowMs: number): void {
    // Записи в порядке вставки, срок у всех одинаков: истёкшие — в начале.
    for (const [k, until] of this.#until) {
      if (until > nowMs) break;
      this.#until.delete(k);
    }
    const key = `${agent_code}\u0000${nonce}`;
    this.#until.delete(key);
    this.#until.set(key, nowMs + this.ttlMs);
  }

  get size(): number {
    return this.#until.size;
  }
}

/** Методы, доступные приостановленному и исключённому агенту: узнать свой статус (РП23 п. 6.3). */
const STATUS_EXEMPT = new Set(["GET /pao/v1/agent"]);

export interface PaoVerifierOptions {
  readonly skewSec: number;
  readonly now?: () => Date;
  readonly nonces?: NonceStore;
  /** Проверка подписи по алгоритму ключа — точка расширения РП5; по умолчанию ed25519. */
  readonly verifier?: Verifier;
}

export class PaoRequestVerifier {
  private readonly now: () => Date;
  readonly nonces: NonceStore;
  private readonly verifier: Verifier;

  constructor(
    private readonly sources: PaoAuthSources,
    private readonly opts: PaoVerifierOptions,
  ) {
    this.now = opts.now ?? (() => new Date());
    this.nonces = opts.nonces ?? new NonceStore(2 * opts.skewSec * 1000);
    this.verifier = opts.verifier ?? ed25519Verifier;
  }

  /** Порядок РП23 п. 6: AGENT_UNKNOWN → SIGNATURE_INVALID / AGENT_KEY_REVOKED → AGENT_SUSPENDED. Любой сбой — отказ. */
  verify(req: PaoRequest): PaoAuthResult {
    // Повтор заголовка — неоднозначность, не догадка (инвариант 3).
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined) continue;
      if (typeof value !== "string") return fail("SIGNATURE_INVALID");
      headers[name.toLowerCase()] = value;
    }

    const agentCode = headers["x-agent-code"];
    const agent = agentCode ? this.sources.getAgent(agentCode) : undefined;
    if (!agentCode || !agent) return { ok: false, code: "AGENT_UNKNOWN", norm: "A2 п. 5.1" };

    const nonce = headers["x-nonce"] ?? "";
    const now = this.now().getTime();
    // Алгоритм подписи — атрибут ключа (РП5): alg из Signature-Input должен совпасть с alg ключа.
    let keyAlg: string | undefined;
    const lookupKey = (kid: string): KeyForVerify | undefined => {
      const key = this.sources.lookupKey(agent.agent_code, kid);
      keyAlg = key?.alg;
      return key;
    };
    const verifier: Verifier = {
      verify: (alg, publicKey, data, sig) => alg === keyAlg && this.verifier.verify(alg, publicKey, data, sig),
    };

    let result: ReturnType<typeof verifyRequest>;
    try {
      result = verifyRequest(
        { method: req.method, path: req.path, query: req.query, headers, body: req.body },
        lookupKey,
        {
          now,
          skewSec: this.opts.skewSec,
          // Только проверка: запоминается после успешной проверки подписи (РП23 п. 6.2).
          seenNonce: (n) => n === "" || this.nonces.has(agent.agent_code, n, now),
          verifier,
        },
      );
    } catch {
      return fail("SIGNATURE_INVALID");
    }
    if (!result.ok) return fail(result.code);
    this.nonces.remember(agent.agent_code, nonce, now);

    if (agent.status !== "ACTIVE" && !STATUS_EXEMPT.has(`${req.method.toUpperCase()} ${req.path}`)) {
      return { ok: false, code: "AGENT_SUSPENDED", norm: "A2 п. 7.1" };
    }
    return { ok: true, agent, kid: result.kid };
  }
}

const fail = (code: "SIGNATURE_INVALID" | "AGENT_KEY_REVOKED"): PaoAuthResult => ({
  ok: false,
  code,
  norm: code === "AGENT_KEY_REVOKED" ? "A2 п. 5.4" : "A2 п. 5.1",
});
