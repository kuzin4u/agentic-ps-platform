// Хранилище реестра: порт и реализация в памяти; PostgreSQL — PgAgentRegistryStore за тем же портом (РП64 п. 1–3).
// Записи агентов и их ключи — в одном порту: допуск неделим, запись и первый ключ вместе (РП23 п. 2).
// Порт асинхронный, кэша нет (РП64 п. 3): статус и ключи читаются из хранилища на каждом обращении; сбой чтения —
// отклонённое обещание, вызывающий отказывает (инвариант 3).
import type { AgentKey } from "./keys.js";
import type { AgentCertificateRecord, AgentRecord, AgentSubscription, Contour } from "./model.js";

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

/**
 * Ограничение схемы agent_certificates (sql/121, CHECK not_after > not_before): то же условие — у хранилища в памяти, чтобы
 * сбой вставки сертификата в транзакции допуска был одинаковым на обоих (РП65 нюанс 13).
 */
export const certificatePeriodValid = (c: Pick<AgentCertificateRecord, "not_before" | "not_after">): boolean =>
  Date.parse(c.not_after) > Date.parse(c.not_before);

export type StatusFields =Pick<AgentRecord, "status" | "status_ground" | "status_changed_at" | "suspended_at">;

export interface AgentRegistryStore {
  get(agent_code: string): Promise<AgentRecord | undefined>;
  /** Коды всех агентов в порядке допуска. */
  agentCodes(): Promise<readonly string[]>;
  /**
   * Ключи агентов ACTIVE этого контура — для каталога ключей (РП22 п. 1), одним чтением (КТ1 ч. 2а № 10): порядок — допуск
   * агента, затем порядок ключей агента (как keysOf). Срок и отзыв ключа отбирает вызывающий по своим часам.
   */
  catalogKeys(contour: Contour): Promise<readonly AgentKey[]>;
  /** Оператор, которому принадлежат версии агента «сторона : идентификатор»; нет версий — undefined. */
  ownerOf(issuer: string, id: string): Promise<string | undefined>;
  /**
   * Вставка записи вместе с первым ключом и сертификатом mTLS, если он выдан, — неделимо (РП23 п. 2, РП65 п. 3). Код занят
   * или «сторона : идентификатор» принадлежит другому оператору — AgentCodeTakenError (A2 п. 4.1, РП21 п. 2); kid уже
   * есть — KeyTakenError; серийный номер уже есть — исключение. При ошибке не сохраняется ничего.
   */
  insert(record: AgentRecord, firstKey: AgentKey, certificate?: AgentCertificateRecord): Promise<void>;
  /**
   * Изменение только полей статуса при совпадении row_version; не совпала — undefined (конкурентное изменение).
   * row_version записи агента растёт только здесь: по ней event_id события смены статуса (РП54 п. 2, КТ1 № 3).
   */
  updateStatus(agent_code: string, expectedRowVersion: number, fields: StatusFields): Promise<AgentRecord | undefined>;

  getKey(kid: string): Promise<AgentKey | undefined>;
  keysOf(agent_code: string): Promise<readonly AgentKey[]>;
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
  ): Promise<boolean>;
  /** Отзыв при совпадении row_version; не совпала — undefined. */
  revokeKey(kid: string, expectedRowVersion: number, revoked_at: string): Promise<AgentKey | undefined>;

  /** Сертификат mTLS по серийному номеру (РП65 п. 3); нет — undefined. Чтение — на каждом обращении, без кэша. */
  getCertificate(serial: string): Promise<AgentCertificateRecord | undefined>;
  /** Сертификаты агента в порядке выпуска. */
  certificatesOf(agent_code: string): Promise<readonly AgentCertificateRecord[]>;
  /**
   * Отзыв сертификата — необратим (РП65 п. 3): уже отозванный возвращается без изменений с прежним revoked_at
   * (как РП23 доп. 3); нет такого — undefined.
   */
  revokeCertificate(serial: string, revoked_at: string): Promise<AgentCertificateRecord | undefined>;

  /** Подписка агента на события (РП40 п. 1); нет подписки — undefined. */
  subscriptionOf(agent_code: string): Promise<AgentSubscription | undefined>;
  /** Замена подписки целиком; агента нет — false. Статус не проверяется: push проверяет его перед каждой отправкой (РП40 п. 6). */
  setSubscription(agent_code: string, subscription: AgentSubscription): Promise<boolean>;
}

/** Память (стенд, dev без DATABASE_URL — РП64 п. 7): тело каждого метода без await — один процесс, одна очередь. */
export class InMemoryAgentRegistryStore implements AgentRegistryStore {
  readonly #byCode = new Map<string, AgentRecord>();
  readonly #owners = new Map<string, string>();
  readonly #keys = new Map<string, AgentKey>();
  readonly #keysByAgent = new Map<string, string[]>();
  readonly #subscriptions = new Map<string, AgentSubscription>();
  readonly #certificates = new Map<string, AgentCertificateRecord>();

  async get(agent_code: string): Promise<AgentRecord | undefined> {
    return this.#byCode.get(agent_code);
  }

  async agentCodes(): Promise<readonly string[]> {
    return [...this.#byCode.keys()];
  }

  async ownerOf(issuer: string, id: string): Promise<string | undefined> {
    return this.#owners.get(`${issuer}\u0000${id}`);
  }

  async catalogKeys(contour: Contour): Promise<readonly AgentKey[]> {
    return [...this.#byCode.values()]
      .filter((r) => r.status === "ACTIVE" && r.contour === contour)
      .flatMap((r) => (this.#keysByAgent.get(r.agent_code) ?? []).map((kid) => this.#keys.get(kid) as AgentKey));
  }

  async insert(record: AgentRecord, firstKey: AgentKey, certificate?: AgentCertificateRecord): Promise<void> {
    const key = `${record.issuer}\u0000${record.id}`;
    const owner = this.#owners.get(key);
    if (this.#byCode.has(record.agent_code) || (owner !== undefined && owner !== record.operator)) {
      throw new AgentCodeTakenError(record.agent_code);
    }
    if (firstKey.agent_code !== record.agent_code) throw new Error("Первый ключ не этого агента");
    if (this.#keys.has(firstKey.kid)) throw new KeyTakenError(firstKey.kid);
    if (certificate && certificate.agent_code !== record.agent_code) throw new Error("Сертификат не этого агента");
    if (certificate && this.#certificates.has(certificate.serial)) throw new Error(`Серийный номер уже выдан: ${certificate.serial}`);
    if (certificate && !certificatePeriodValid(certificate)) throw new Error(`Срок сертификата пуст: ${certificate.serial}`);
    this.#owners.set(key, record.operator);
    this.#byCode.set(record.agent_code, Object.freeze({ ...record }));
    this.#keys.set(firstKey.kid, Object.freeze({ ...firstKey }));
    this.#keysByAgent.set(record.agent_code, [firstKey.kid]);
    if (certificate) this.#certificates.set(certificate.serial, Object.freeze({ ...certificate }));
  }

  async getCertificate(serial: string): Promise<AgentCertificateRecord | undefined> {
    return this.#certificates.get(serial);
  }

  async certificatesOf(agent_code: string): Promise<readonly AgentCertificateRecord[]> {
    return [...this.#certificates.values()].filter((c) => c.agent_code === agent_code);
  }

  async revokeCertificate(serial: string, revoked_at: string): Promise<AgentCertificateRecord | undefined> {
    const cur = this.#certificates.get(serial);
    if (!cur || cur.revoked_at !== null) return cur;
    const next = Object.freeze({ ...cur, revoked_at });
    this.#certificates.set(serial, next);
    return next;
  }

  async updateStatus(agent_code: string, expectedRowVersion: number, fields: StatusFields): Promise<AgentRecord | undefined> {
    const cur = this.#byCode.get(agent_code);
    if (!cur || cur.row_version !== expectedRowVersion) return undefined;
    const next = Object.freeze({
      ...cur,
      status: fields.status,
      status_ground: fields.status_ground,
      status_changed_at: fields.status_changed_at,
      suspended_at: fields.suspended_at,
      row_version: cur.row_version + 1,
    });
    this.#byCode.set(agent_code, next);
    return next;
  }

  async getKey(kid: string): Promise<AgentKey | undefined> {
    return this.#keys.get(kid);
  }

  async keysOf(agent_code: string): Promise<readonly AgentKey[]> {
    return (this.#keysByAgent.get(agent_code) ?? []).map((kid) => this.#keys.get(kid) as AgentKey);
  }

  async addKey(
    key: AgentKey,
    expected: ReadonlyMap<string, number>,
    shorten: ReadonlyMap<string, string>,
    agentRowVersion: number,
  ): Promise<boolean> {
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

  async revokeKey(kid: string, expectedRowVersion: number, revoked_at: string): Promise<AgentKey | undefined> {
    const cur = this.#keys.get(kid);
    if (!cur || cur.row_version !== expectedRowVersion || cur.revoked_at !== null) return undefined;
    const next = Object.freeze({ ...cur, revoked_at, row_version: cur.row_version + 1 });
    this.#keys.set(kid, next);
    return next;
  }

  async subscriptionOf(agent_code: string): Promise<AgentSubscription | undefined> {
    return this.#subscriptions.get(agent_code);
  }

  async setSubscription(agent_code: string, subscription: AgentSubscription): Promise<boolean> {
    if (!this.#byCode.has(agent_code)) return false;
    this.#subscriptions.set(agent_code, Object.freeze({ url: subscription.url, events: Object.freeze([...subscription.events]) }));
    return true;
  }
}
