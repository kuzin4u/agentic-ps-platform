// Хранилище реестра: порт и реализация в памяти. PostgreSQL — за тем же портом вместе с журналом согласий (PS-06).
// Записи агентов и их ключи — в одном порту: допуск неделим, запись и первый ключ вместе (РП23 п. 2).
import type { AgentKey } from "./keys.js";
import type { AgentRecord } from "./model.js";

export class AgentCodeTakenError extends Error {
  constructor(readonly agent_code: string) {
    super(`Код агента уже выдан: ${agent_code}`);
    this.name = "AgentCodeTakenError";
  }
}

export class KeyTakenError extends Error {
  constructor(readonly kid: string) {
    super(`Ключ уже зарегистрирован: ${kid}`);
    this.name = "KeyTakenError";
  }
}

export type StatusFields = Pick<AgentRecord, "status" | "status_ground" | "status_changed_at">;

export interface AgentRegistryStore {
  get(agent_code: string): AgentRecord | undefined;
  /** Коды всех агентов в порядке допуска — для каталога ключей (РП22 п. 1). */
  agentCodes(): readonly string[];
  /** Оператор, которому принадлежат версии агента «сторона : идентификатор»; нет версий — undefined. */
  ownerOf(issuer: string, id: string): string | undefined;
  /**
   * Вставка записи вместе с первым ключом — неделимо (РП23 п. 2). Код занят или «сторона : идентификатор» принадлежит
   * другому оператору — AgentCodeTakenError (A2 п. 4.1, РП21 п. 2); kid уже есть — KeyTakenError. При ошибке не сохраняется ничего.
   */
  insert(record: AgentRecord, firstKey: AgentKey): void;
  /** Изменение только полей статуса при совпадении row_version; не совпала — undefined (конкурентное изменение). */
  updateStatus(agent_code: string, expectedRowVersion: number, fields: StatusFields): AgentRecord | undefined;

  getKey(kid: string): AgentKey | undefined;
  keysOf(agent_code: string): readonly AgentKey[];
  /**
   * Новый ключ и сокращение valid_to остальных — неделимо (РП23 п. 4). `expected` — kid → row_version всех ключей агента
   * на момент чтения, `agentRowVersion` — версия записи агента, по которой проверен статус (РП23, дополнения):
   * изменилось что-то из них — false (конкурентное изменение). kid уже есть — KeyTakenError.
   */
  addKey(
    key: AgentKey,
    expected: ReadonlyMap<string, number>,
    shorten: ReadonlyMap<string, string>,
    agentRowVersion: number,
  ): boolean;
  /** Отзыв при совпадении row_version; не совпала — undefined. */
  revokeKey(kid: string, expectedRowVersion: number, revoked_at: string): AgentKey | undefined;
}

export class InMemoryAgentRegistryStore implements AgentRegistryStore {
  readonly #byCode = new Map<string, AgentRecord>();
  readonly #owners = new Map<string, string>();
  readonly #keys = new Map<string, AgentKey>();
  readonly #keysByAgent = new Map<string, string[]>();

  get(agent_code: string): AgentRecord | undefined {
    return this.#byCode.get(agent_code);
  }

  agentCodes(): readonly string[] {
    return [...this.#byCode.keys()];
  }

  ownerOf(issuer: string, id: string): string | undefined {
    return this.#owners.get(`${issuer}\u0000${id}`);
  }

  insert(record: AgentRecord, firstKey: AgentKey): void {
    const key = `${record.issuer}\u0000${record.id}`;
    const owner = this.#owners.get(key);
    if (this.#byCode.has(record.agent_code) || (owner !== undefined && owner !== record.operator)) {
      throw new AgentCodeTakenError(record.agent_code);
    }
    if (firstKey.agent_code !== record.agent_code) throw new Error("Первый ключ не этого агента");
    if (this.#keys.has(firstKey.kid)) throw new KeyTakenError(firstKey.kid);
    this.#owners.set(key, record.operator);
    this.#byCode.set(record.agent_code, Object.freeze({ ...record }));
    this.#keys.set(firstKey.kid, Object.freeze({ ...firstKey }));
    this.#keysByAgent.set(record.agent_code, [firstKey.kid]);
  }

  updateStatus(agent_code: string, expectedRowVersion: number, fields: StatusFields): AgentRecord | undefined {
    const cur = this.#byCode.get(agent_code);
    if (!cur || cur.row_version !== expectedRowVersion) return undefined;
    const next = Object.freeze({
      ...cur,
      status: fields.status,
      status_ground: fields.status_ground,
      status_changed_at: fields.status_changed_at,
      row_version: cur.row_version + 1,
    });
    this.#byCode.set(agent_code, next);
    return next;
  }

  getKey(kid: string): AgentKey | undefined {
    return this.#keys.get(kid);
  }

  keysOf(agent_code: string): readonly AgentKey[] {
    return (this.#keysByAgent.get(agent_code) ?? []).map((kid) => this.#keys.get(kid) as AgentKey);
  }

  addKey(
    key: AgentKey,
    expected: ReadonlyMap<string, number>,
    shorten: ReadonlyMap<string, string>,
    agentRowVersion: number,
  ): boolean {
    const kids = this.#keysByAgent.get(key.agent_code);
    if (!kids) throw new Error(`Агента нет в реестре: ${key.agent_code}`);
    if (this.#keys.has(key.kid)) throw new KeyTakenError(key.kid);
    if (this.#byCode.get(key.agent_code)?.row_version !== agentRowVersion) return false;
    const same =
      kids.length === expected.size && kids.every((kid) => this.#keys.get(kid)?.row_version === expected.get(kid));
    if (!same || [...shorten.keys()].some((kid) => !expected.has(kid))) return false;
    for (const [kid, valid_to] of shorten) {
      const cur = this.#keys.get(kid) as AgentKey;
      this.#keys.set(kid, Object.freeze({ ...cur, valid_to, row_version: cur.row_version + 1 }));
    }
    this.#keys.set(key.kid, Object.freeze({ ...key }));
    kids.push(key.kid);
    return true;
  }

  revokeKey(kid: string, expectedRowVersion: number, revoked_at: string): AgentKey | undefined {
    const cur = this.#keys.get(kid);
    if (!cur || cur.row_version !== expectedRowVersion || cur.revoked_at !== null) return undefined;
    const next = Object.freeze({ ...cur, revoked_at, row_version: cur.row_version + 1 });
    this.#keys.set(kid, next);
    return next;
  }
}
