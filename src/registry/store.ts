// Хранилище реестра: порт и реализация в памяти. PostgreSQL — за тем же портом вместе с журналом согласий (PS-06).
import type { AgentRecord } from "./model.js";

export class AgentCodeTakenError extends Error {
  constructor(readonly agent_code: string) {
    super(`Код агента уже выдан: ${agent_code}`);
    this.name = "AgentCodeTakenError";
  }
}

export type StatusFields = Pick<AgentRecord, "status" | "status_ground" | "status_changed_at">;

export interface AgentRegistryStore {
  get(agent_code: string): AgentRecord | undefined;
  /** Оператор, которому принадлежат версии агента «сторона : идентификатор»; нет версий — undefined. */
  ownerOf(issuer: string, id: string): string | undefined;
  /**
   * Вставка новой записи. Неделимо с проверкой: код занят или «сторона : идентификатор» принадлежит
   * другому оператору — AgentCodeTakenError (A2 п. 4.1, РП21 п. 2).
   */
  insert(record: AgentRecord): void;
  /** Изменение только полей статуса при совпадении row_version; не совпала — undefined (конкурентное изменение). */
  updateStatus(agent_code: string, expectedRowVersion: number, fields: StatusFields): AgentRecord | undefined;
}

export class InMemoryAgentRegistryStore implements AgentRegistryStore {
  readonly #byCode = new Map<string, AgentRecord>();
  readonly #owners = new Map<string, string>();

  get(agent_code: string): AgentRecord | undefined {
    return this.#byCode.get(agent_code);
  }

  ownerOf(issuer: string, id: string): string | undefined {
    return this.#owners.get(`${issuer}\u0000${id}`);
  }

  insert(record: AgentRecord): void {
    const key = `${record.issuer}\u0000${record.id}`;
    const owner = this.#owners.get(key);
    if (this.#byCode.has(record.agent_code) || (owner !== undefined && owner !== record.operator)) {
      throw new AgentCodeTakenError(record.agent_code);
    }
    this.#owners.set(key, record.operator);
    this.#byCode.set(record.agent_code, Object.freeze({ ...record }));
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
}
