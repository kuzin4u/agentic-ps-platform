// П1 Ключи агентов: регистрация с перекрытием, отзыв, поиск для проверки подписи (A2 п. 5, ФП2, РП23).
// Ключ ищется только среди ключей своего агента: kid чужого агента — как неизвестный (РП23 п. 3, инвариант 5).
import {
  DEFAULT_KEY_ALGORITHMS,
  keyStatus,
  newAgentKey,
  overlapEnd,
  parseKey,
  toPaoKey,
  type AgentKey,
  type KeyAlgorithm,
  type KeyPolicy,
  type KeyStatus,
} from "./keys.js";
import { agentJwk, type AgentJwks } from "./jwks.js";
import type { Contour } from "./model.js";
import { AgentNotFoundError, ConcurrentChangeError } from "./registry.js";
import { KeyTakenError, type AgentRegistryStore } from "./store.js";
import type { Key } from "../shared/pao.js";

/**
 * Причина отказа в ключе — только для журнала процесса (РП31 п. 2): агенту — один код KEY_INVALID.
 * ALG — alg не из перечня контура; KEY — ключ не разбирается, неканоническая запись или слабый ключ; TAKEN — ключ у другого
 * агента или свой отозванный или истёкший (свой действующий возвращается, РП23 доп. 7).
 */
export type KeyInvalidReason = "ALG" | "KEY" | "TAKEN";

export class KeyInvalidError extends Error {
  constructor(
    readonly agent_code: string,
    readonly reason: KeyInvalidReason,
  ) {
    super(`Ключ не принят (РП23 п. 2–3, ${reason}): ${agent_code}`);
    this.name = "KeyInvalidError";
  }
}

export class KeyNotFoundError extends Error {
  constructor(
    readonly agent_code: string,
    readonly kid: string,
  ) {
    super(`У агента ${agent_code} нет ключа ${kid}`);
    this.name = "KeyNotFoundError";
  }
}

/** Агент не ACTIVE при регистрации ключа по ПАО (РП23 п. 6.3): смена ключа приостановленным — через оператора (PS-31). */
export class AgentNotActiveError extends Error {
  constructor(readonly agent_code: string) {
    super(`Агент не ACTIVE, ключ по ПАО не регистрируется: ${agent_code}`);
    this.name = "AgentNotActiveError";
  }
}

export class AgentExcludedError extends Error {
  constructor(readonly agent_code: string) {
    super(`Агент исключён, ключи не регистрируются: ${agent_code}`);
    this.name = "AgentExcludedError";
  }
}

/** Ключ для проверки подписи — вход lookupKey в agentic-core verifyRequest. */
export interface KeyForVerify {
  readonly alg: string;
  readonly publicKey: string;
  readonly status: KeyStatus;
}

export interface AgentKeysOptions {
  readonly keys: KeyPolicy;
  readonly now?: () => Date;
  readonly algorithms?: Readonly<Record<Contour, readonly KeyAlgorithm[]>>;
}

export class AgentKeys {
  private readonly now: () => Date;
  private readonly policy: KeyPolicy;
  private readonly algorithms: Readonly<Record<Contour, readonly KeyAlgorithm[]>>;

  constructor(
    private readonly store: AgentRegistryStore,
    opts: AgentKeysOptions,
  ) {
    this.policy = opts.keys;
    this.now = opts.now ?? (() => new Date());
    this.algorithms = opts.algorithms ?? DEFAULT_KEY_ALGORITHMS;
  }

  /**
   * Новый ключ агента (A2 п. 5.3): valid_to = now + key_ttl_days; у остальных действующих ключей valid_to сокращается
   * до now + key_overlap_days (РП23 п. 4). Исключённому агенту — отказ; приостановленному — можно (смена ключа при компрометации);
   * проверка статуса неделима с добавлением ключа (РП23, дополнения).
   */
  register(agent_code: string, input: unknown, opts: { readonly requireActive?: boolean } = {}): AgentKey {
    const rec = this.store.get(agent_code);
    if (!rec) throw new AgentNotFoundError(agent_code);
    if (rec.status === "EXCLUDED") throw new AgentExcludedError(agent_code);
    // По ПАО — только ACTIVE; статус проверен по той же версии записи, что и вставка ниже (гонка — ConcurrentChangeError).
    if (opts.requireActive && rec.status !== "ACTIVE") throw new AgentNotActiveError(agent_code);
    const i = (typeof input === "object" && input !== null ? input : {}) as Record<string, unknown>;
    const algorithms = this.algorithms[rec.contour];
    const alg = Object.hasOwn(i, "alg") ? i.alg : undefined;
    const parsed = parseKey(algorithms, alg, Object.hasOwn(i, "public_key") ? i.public_key : undefined);
    if (!parsed) throw new KeyInvalidError(agent_code, algorithms.some((a) => a.alg === alg) ? "KEY" : "ALG");
    // Идемпотентность ресурса (РП23 доп. 7): свой действующий ключ — тот же ключ без изменений.
    const existing = this.ownActive(agent_code, parsed.kid);
    if (existing) return existing;
    if (this.store.getKey(parsed.kid)) throw new KeyInvalidError(agent_code, "TAKEN");

    const now = this.now();
    const end = overlapEnd(now, this.policy);
    const current = this.store.keysOf(agent_code);
    const expected = new Map(current.map((k) => [k.kid, k.row_version]));
    const shorten = new Map(
      current
        .filter((k) => keyStatus(k, now) === "ACTIVE" && Date.parse(k.valid_to) > end)
        .map((k) => [k.kid, new Date(end).toISOString()]),
    );
    const key = newAgentKey(agent_code, parsed, now, this.policy);
    let ok: boolean;
    try {
      // Статус проверен по версии записи агента: исключение между проверкой и вставкой — конкурентное изменение.
      ok = this.store.addKey(key, expected, shorten, rec.row_version);
    } catch (e) {
      if (e instanceof KeyTakenError) {
        // Одновременная вставка того же ключа: свой действующий — тот же ответ, иначе — занят (РП23 доп. 7).
        const raced = this.ownActive(agent_code, parsed.kid);
        if (raced) return raced;
        throw new KeyInvalidError(agent_code, "TAKEN");
      }
      throw e;
    }
    if (!ok) throw new ConcurrentChangeError(agent_code);
    return this.store.getKey(key.kid) as AgentKey;
  }

  /** Отзыв своего ключа, включая последний (РП23 п. 5). Необратим; повторный отзыв возвращает отозванный ключ. */
  revoke(agent_code: string, kid: string): AgentKey {
    const cur = this.own(agent_code, kid);
    if (!cur) throw new KeyNotFoundError(agent_code, kid);
    if (cur.revoked_at !== null) return cur;
    const next = this.store.revokeKey(kid, cur.row_version, this.now().toISOString());
    if (!next) throw new ConcurrentChangeError(agent_code);
    return next;
  }

  /** Ключи агента в виде схемы Key ПАО, со статусом на сейчас. */
  list(agent_code: string): Key[] {
    const now = this.now();
    return this.store.keysOf(agent_code).map((k) => toPaoKey(k, now));
  }

  /** Ключ для проверки подписи: только среди ключей агента agent_code; статус — на момент вызова (РП23 п. 3–4). */
  lookup(agent_code: string, kid: string): KeyForVerify | undefined {
    const key = this.own(agent_code, kid);
    return key && { alg: key.alg, publicKey: key.public_key, status: keyStatus(key, this.now()) };
  }

  /**
   * Каталог ключей агентов для продавцов и площадок (РП22 п. 1–2): только действующие ключи агентов ACTIVE;
   * отозванный, истёкший ключ и ключи приостановленного или исключённого агента в каталог не попадают.
   * Одна функция для эмулятора продавцов (PS-12) и HTTP-адреса каталога (PS-30).
   * Только агенты своего контура (РП56 п. 2): ключ песочницы в каталоге контура оператора — подпись прошла бы у боевого продавца.
   */
  jwks(contour: Contour): AgentJwks {
    const now = this.now();
    const keys = this.store
      .agentCodes()
      .filter((code) => {
        const rec = this.store.get(code);
        return rec?.status === "ACTIVE" && rec.contour === contour;
      })
      .flatMap((code) => this.store.keysOf(code))
      .filter((k) => keyStatus(k, now) === "ACTIVE" && Date.parse(k.valid_from) <= now.getTime())
      .map(agentJwk)
      .filter((k) => k !== null);
    return { keys };
  }

  private ownActive(agent_code: string, kid: string): AgentKey | undefined {
    const key = this.own(agent_code, kid);
    return key && keyStatus(key, this.now()) === "ACTIVE" ? key : undefined;
  }

  private own(agent_code: string, kid: string): AgentKey | undefined {
    const key = this.store.getKey(kid);
    return key && key.agent_code === agent_code ? key : undefined;
  }
}
