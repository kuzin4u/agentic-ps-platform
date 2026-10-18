// П2 Журнал согласий над журналом ядра (РП14): запрос мандата и чтение со статусом-свёрткой (PS-06 К1.2).
// Проверка запроса по схеме ПАО, идемпотентность и HTTP — К1.3; id от (агент, ключ) и повтор — К2.1 (РП33 доп.);
// подпись принципала по подписи участника — К2.4 (РП36); отзыв клиентом и отказ агента — К2.6, verify — К2.7,
// выписка — К2.8 (РП38).
import {
  AsyncHashChainJournal,
  canonicalJson,
  entryHash,
  GENESIS_HASH,
  sha256Hex,
  type AsyncJournalStore,
  type JournalEntry,
} from "@kuzin4u/agentic-core";
import type { EvidenceV14, Mandate, MandateRequest, MandateVerify } from "../shared/pao.js";
import {
  ConsentIntegrityError,
  ConsentKeyReused,
  consentChain,
  deriveStatus,
  mandateIdFor,
  newSalt,
  subjectCommitment,
  withParentStatus,
  ConsentStateUnknown,
  type MandateDecisionPayload,
  type MandateRelinquishPayload,
  type MandateRequestedPayload,
  type MandateRevocationPayload,
  type MandateStatus,
  type MandateSubject,
  type MandateTerms,
} from "./model.js";
import { ConsentRowConflict, type ConsentStore, type MandateIndexRow } from "./store.js";
import { assertNarrows, ConsentRequestRejected, pickSubject, pickTerms } from "./terms.js";
import type { Params } from "../shared/config.js";

/** Пороги усиленной подписи (A7 п. 3.2) — стендовые параметры, не константы (PARAMS.md). */
export type SignaturePolicy = Pick<Params, "qualified_signature_above_kop" | "qualified_signature_above_days">;

/** Основания отказа в записи решения клиента (РП36 доп.). */
export type SignRejectReason =
  | "SIGNATURE_INVALID"
  | "MANDATE_NOT_FOUND"
  | "MANDATE_HASH_MISMATCH"
  | "MANDATE_NOT_PENDING"
  | "QUALIFIED_SIGNATURE_REQUIRED";

/**
 * Запись участника (решение клиента, РП36; отзыв, РП38) не принята: запись журнала не пишется. status — статус мандата
 * на момент проверки, если он известен.
 */
export class ConsentSignRejected extends Error {
  constructor(
    readonly reason: SignRejectReason,
    readonly mandateId: string,
    readonly status?: MandateStatus,
  ) {
    super(`CONSENT_SIGN_REJECTED: ${reason}: ${mandateId}${status ? ` (${status})` : ""}`);
  }
}

/** Что видит банк на экране мандата (РП36 п. 3): хэш записи — тот же, что в журнале и в Mandate.hash. */
export interface MandateSigningView {
  readonly id: string;
  readonly hash: string;
  readonly status: MandateStatus;
  readonly principal_ref: string;
  readonly amount_limit: number;
  readonly currency: string;
  readonly valid_to: string;
  readonly subject: string;
  readonly cart: MandateSubject["cart"];
}

const DAY_MS = 86_400_000;

/** Порог в копейках задан для рублей; другая валюта — только усиленная подпись (fail-closed, РП36 доп.). */
const THRESHOLD_CURRENCY = "RUB";

export interface ConsentJournalOptions {
  readonly now?: () => Date;
  /**
   * Порядок отзыва из записи участника (РП37; до PS-20 — PARTICIPANT_KEYS_PATH, TrustedParticipants.revocationOrder).
   * undefined — мандат не пишется: ConsentStateUnknown → 503 STATE_UNAVAILABLE (fail-closed, инвариант 3).
   */
  readonly revocationOrder: () => string | undefined;
}

/** Мандат, прочитанный из журнала: цепочка проверена, предмет сверен с обязательством. */
interface LoadedMandate {
  readonly row: MandateIndexRow;
  readonly head: JournalEntry;
  readonly subj: MandateSubject;
  readonly status: MandateStatus;
}

export class ConsentJournal {
  private readonly now: () => Date;
  private readonly revocationOrder: () => string | undefined;
  /**
   * Лок записи по мандату: решение банка, отзыв клиентом и отказ агента по одному мандату — по очереди внутри процесса
   * (РП36 доп. п. 4, РП38 п. 4); между экземплярами — дубль решения и записи после отзыва терпит свёртка (РП38 п. 5).
   */
  private readonly writing = new Map<string, Promise<unknown>>();

  constructor(
    private readonly store: ConsentStore,
    opts: ConsentJournalOptions,
  ) {
    this.now = opts.now ?? (() => new Date());
    this.revocationOrder = opts.revocationOrder;
  }

  /** beforeWrite — перед каждой попыткой вставки: ядро повторяет вставку при гонке конца цепочки (РП33 доп. п. 8). */
  private chainJournal(chain: string, beforeWrite?: () => void): AsyncHashChainJournal {
    const inner = this.store.journal(chain);
    const store: AsyncJournalStore = beforeWrite
      ? {
          ...(inner.genesis !== undefined ? { genesis: inner.genesis } : {}),
          last: () => inner.last(),
          all: () => inner.all(),
          append: async (e) => {
            beforeWrite();
            return inner.append(e);
          },
        }
      : inner;
    return new AsyncHashChainJournal(store, () => this.now().toISOString());
  }

  /**
   * Запрос мандата агентом: запись MANDATE_REQUESTED, статус PENDING_SIGNATURE (подпись — у принципала в банке).
   * agent_code — из проверенного обращения, не из тела (инвариант 5). В запись — только поля перечня (terms.ts).
   * CART под INTENT — только под действующим (ACTIVE) родителем этого агента и только сужением (A7 п. 5).
   * Порядок: индекс, предмет, запись журнала; запись журнала — источник истины (store.ts).
   * id — от (агент, хэш Idempotency-Key) (РП33 доп.): мандат по id уже начат — повтор (resume), не второй мандат.
   * beforeWrite — перед каждой записью в хранилище: предел времени обработчика (РП33 доп., меньше аренды ключа).
   */
  async request(
    agent_code: string,
    idempotencyKeyHash: string,
    req: MandateRequest,
    beforeWrite: () => void = () => {},
  ): Promise<Mandate> {
    const id = mandateIdFor(agent_code, idempotencyKeyHash);
    const row = await this.store.getMandate(id);
    if (row) return this.resume(row, agent_code, req, beforeWrite);
    const now = this.now();
    const terms = await this.withRevocationOrder(id, agent_code, pickTerms(agent_code, req, now, ""));
    const subj = pickSubject(req, terms.amount_limit);
    const chain = await this.chainFor(id, agent_code, terms, subj);
    beforeWrite();
    try {
      await this.store.insertMandate({ id, chain, agent_code, created_at: now.toISOString(), terms_hash: termsHash(terms) });
    } catch (err) {
      // Тот же ключ начат другим обработчиком между чтением и вставкой — дальше как повтор.
      const raced = err instanceof ConsentRowConflict ? await this.store.getMandate(id) : undefined;
      if (!raced) throw err;
      return this.resume(raced, agent_code, req, beforeWrite);
    }
    return this.complete(id, chain, terms, subj, undefined, beforeWrite);
  }

  /**
   * Повтор по тому же ключу (РП33 доп. п. 6–7). Запись журнала есть — тот же мандат, если запрос совпадает с
   * записанным, в любой срок (срок не проверяется); иначе ConsentKeyReused. Запрос, не проходящий проверку реквизитов, —
   * тоже другой запрос: ключ уже занят мандатом. Запись не завершилась (индекс или индекс и предмет) — сохранённая
   * часть (реквизиты по хэшу в индексе, цепочка, предмет) сверяется с запросом, чужой запрос не доделывается; затем
   * запись доделывается как новая: срок и родитель проверяются заново.
   */
  private async resume(
    row: MandateIndexRow,
    agent_code: string,
    req: MandateRequest,
    beforeWrite: () => void,
  ): Promise<Mandate> {
    if (row.agent_code !== agent_code) throw new ConsentIntegrityError(row.id, "agent_code индекса ≠ id");
    let terms: MandateTerms;
    let subj: MandateSubject;
    try {
      // Порядок отзыва — не из тела агента: у записанного мандата — записанный, иначе — как у новой записи (РП37 п. 5).
      terms = pickTerms(agent_code, req, null, "");
      subj = pickSubject(req, terms.amount_limit);
    } catch (err) {
      if (err instanceof ConsentRequestRejected) throw new ConsentKeyReused(row.id);
      throw err;
    }
    const m = await this.load(row.id, agent_code);
    if (m) {
      const recorded = m.head.payload as MandateRequestedPayload;
      // Сверка — только реквизитов агента: смена конфигурации участника после записи повтор не ломает (ПАО §2).
      terms = { ...terms, revocation_order: recorded.revocation_order };
      if (!sameTerms(recorded, terms) || canonicalJson(m.subj) !== canonicalJson(subj)) {
        throw new ConsentKeyReused(row.id);
      }
      return this.toMandate(row.id, m.head, m.subj, m.status);
    }
    terms = await this.withRevocationOrder(row.id, agent_code, terms);
    const expectedChain = terms.parent_id ? (await this.store.getMandate(terms.parent_id))?.chain : consentChain(row.id);
    if (row.chain !== expectedChain || row.terms_hash !== termsHash(terms)) throw new ConsentKeyReused(row.id);
    const s = await this.store.getSubject(row.id);
    if (s && s.subject_json !== canonicalJson(subj)) throw new ConsentKeyReused(row.id);
    const fresh = pickTerms(agent_code, req, this.now(), terms.revocation_order);
    await this.chainFor(row.id, agent_code, fresh, subj);
    return this.complete(row.id, row.chain, fresh, subj, s?.salt, beforeWrite);
  }

  /**
   * Порядок отзыва новой записи (РП37): участника нет — мандат не пишется (503, и для CART). Корневой мандат — из записи
   * участника; CART под INTENT — порядок родителя (тот же банк и то же соглашение, РП37 п. 6); родителя нет — значение
   * участника, отказ даст chainFor. Прерванная запись, доделываемая после смены конфигурации, — ConsentKeyReused
   * (хэш реквизитов индекса не совпадёт; РП37 п. 5).
   */
  private async withRevocationOrder(id: string, agent_code: string, terms: MandateTerms): Promise<MandateTerms> {
    const ro = this.revocationOrder();
    if (ro === undefined) throw new ConsentStateUnknown(id, "порядок отзыва участника не задан (РП37)");
    const parent = terms.parent_id ? await this.load(terms.parent_id, agent_code) : undefined;
    const inherited = parent ? (parent.head.payload as MandateRequestedPayload).revocation_order : ro;
    return { ...terms, revocation_order: inherited };
  }

  /** Цепочка записи: своя у корневого мандата; у CART — родителя, после проверки родителя и сужения (A7 п. 5). */
  private async chainFor(id: string, agent_code: string, terms: MandateTerms, subj: MandateSubject): Promise<string> {
    if (!terms.parent_id) return consentChain(id);
    // Родитель — по журналу, как при чтении: индекс без записи, чужой агент — как неизвестный.
    const parent = await this.load(terms.parent_id, agent_code);
    if (!parent) throw new ConsentRequestRejected("PARENT_NOT_FOUND", "parent_id");
    if (parent.status !== "ACTIVE") throw new ConsentRequestRejected("PARENT_NOT_ACTIVE", "parent_id", parent.status);
    assertNarrows(terms, subj, parent.head.payload as MandateRequestedPayload);
    return parent.row.chain;
  }

  /** Предмет (если ещё не записан; иначе — сохранённая соль) и запись журнала. */
  private async complete(
    id: string,
    chain: string,
    terms: MandateTerms,
    subj: MandateSubject,
    savedSalt: string | undefined,
    beforeWrite: () => void,
  ): Promise<Mandate> {
    let salt = savedSalt;
    if (salt === undefined) {
      salt = newSalt();
      beforeWrite();
      await this.store.insertSubject({ mandate_id: id, salt, subject_json: canonicalJson(subj) });
    }
    const payload: MandateRequestedPayload = { ...terms, subject_commitment: subjectCommitment(salt, subj) };
    const entry = await this.chainJournal(chain, beforeWrite).append("MANDATE_REQUESTED", id, payload, terms.parent_id ?? null);
    // Статус — свёрткой и в ответе на запрос, как при чтении. CART — вместе с родителем (РП35): отзыв, записанный между
    // проверкой родителя и записью CART, даёт 201 со статусом REVOKED, а не действующий CART.
    if (!terms.parent_id) return this.toMandate(id, entry, subj, deriveStatus(id, [entry], this.now()));
    const written = await this.load(id, terms.agent_code);
    if (!written) throw new ConsentStateUnknown(id, "CART после записи не читается");
    return this.toMandate(id, written.head, written.subj, written.status);
  }

  /**
   * Решение клиента по мандату — запись MANDATE_SIGNED / MANDATE_REJECTED (РП12, РП36). Порядок: подпись участника над
   * записью (verifySignature; без неё ничего не читается) → мандат по id (агент — из индекса) → mandate_hash = hash
   * записи MANDATE_REQUESTED → статус PENDING_SIGNATURE по свёртке load (у CART — вместе с родителем, РП35 п. 2) →
   * порог усиленной подписи (A7 п. 3.2) → запись. Повтор той же подписи после записи — текущий мандат, второй записи нет.
   */
  async sign(
    d: MandateDecisionPayload,
    verifySignature: (d: MandateDecisionPayload) => boolean,
    policy: SignaturePolicy,
  ): Promise<{ readonly id: string; readonly status: MandateStatus; readonly replayed: boolean }> {
    if (!verifySignature(d)) throw new ConsentSignRejected("SIGNATURE_INVALID", d.mandate_id);
    return this.locked(d.mandate_id, () => this.signLocked(d, policy));
  }

  /** Запись по мандату под локом записи: следующая начинается после окончания предыдущей, в том числе неудачной. */
  private async locked<T>(id: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.writing.get(id) ?? Promise.resolve();
    const run = prev.catch(() => {}).then(fn);
    this.writing.set(id, run);
    try {
      return await run;
    } finally {
      if (this.writing.get(id) === run) this.writing.delete(id);
    }
  }

  private async signLocked(
    d: MandateDecisionPayload,
    policy: SignaturePolicy,
  ): Promise<{ id: string; status: MandateStatus; replayed: boolean }> {
    const id = d.mandate_id;
    const row = await this.store.getMandate(id);
    const m = row && (await this.load(id, row.agent_code));
    if (!row || !m) throw new ConsentSignRejected("MANDATE_NOT_FOUND", id);
    if (d.mandate_hash !== m.head.hash) throw new ConsentSignRejected("MANDATE_HASH_MISMATCH", id);
    if (m.status !== "PENDING_SIGNATURE") {
      // Повтор той же подписи — решение уже записано: текущий статус, без записи.
      const entries = await this.store.journal(row.chain).all();
      const same = entries.some(
        (e) =>
          e.ref === id &&
          (e.kind === "MANDATE_SIGNED" || e.kind === "MANDATE_REJECTED") &&
          canonicalJson(e.payload) === canonicalJson(d),
      );
      if (same) return { id, status: m.status, replayed: true };
      throw new ConsentSignRejected("MANDATE_NOT_PENDING", id, m.status);
    }
    if (d.decision === "SIGN" && d.signature_type === "simple" && needsQualified(m.head.payload as MandateRequestedPayload, m.head.at, policy)) {
      throw new ConsentSignRejected("QUALIFIED_SIGNATURE_REQUIRED", id, m.status);
    }
    // Отзыв с другого экземпляра, записанный между проверкой статуса и вставкой, даёт REQUESTED, REVOKED, SIGNED —
    // свёртка пропускает решение, мандат REVOKED (РП38 п. 5). Внутри процесса отзыв ждёт лок записи: решения после отзыва нет.
    const kind = d.decision === "SIGN" ? "MANDATE_SIGNED" : "MANDATE_REJECTED";
    await this.chainJournal(row.chain).append(kind, id, d, id);
    return { id, status: await this.statusAfterWrite(id, row.agent_code), replayed: false };
  }

  /**
   * Отзыв клиентом через банк — запись MANDATE_REVOKED (РП38 п. 1, 4; A7 п. 6). Порядок, как у sign: подпись участника
   * над записью отзыва → мандат по id → mandate_hash = Mandate.hash → статус по свёртке load (у CART — вместе с
   * родителем). Запись — только при PENDING_SIGNATURE или ACTIVE; иначе полномочий уже нет: текущий статус без записи.
   */
  async revoke(
    d: MandateRevocationPayload,
    verifySignature: (d: MandateRevocationPayload) => boolean,
  ): Promise<{ readonly id: string; readonly status: MandateStatus; readonly replayed: boolean }> {
    if (!verifySignature(d)) throw new ConsentSignRejected("SIGNATURE_INVALID", d.mandate_id);
    return this.locked(d.mandate_id, async () => {
      const id = d.mandate_id;
      const row = await this.store.getMandate(id);
      const m = row && (await this.load(id, row.agent_code));
      if (!row || !m) throw new ConsentSignRejected("MANDATE_NOT_FOUND", id);
      if (d.mandate_hash !== m.head.hash) throw new ConsentSignRejected("MANDATE_HASH_MISMATCH", id);
      if (!revocable(m.status)) return { id, status: m.status, replayed: true };
      await this.chainJournal(row.chain).append("MANDATE_REVOKED", id, d, id);
      return { id, status: await this.statusAfterWrite(id, row.agent_code), replayed: false };
    });
  }

  /**
   * Отказ агента от полномочий — запись MANDATE_RELINQUISHED (РП38 п. 3–4; A7 п. 6). Только свой мандат: чужой и
   * неизвестный — undefined (404). Запись — только при PENDING_SIGNATURE или ACTIVE; иначе — текущий мандат без записи.
   */
  async relinquish(id: string, agent_code: string, kid: string): Promise<Mandate | undefined> {
    return this.locked(id, async () => {
      const m = await this.load(id, agent_code);
      if (!m) return undefined;
      if (!revocable(m.status)) return this.toMandate(id, m.head, m.subj, m.status);
      const payload: MandateRelinquishPayload = { agent_code, kid };
      await this.chainJournal(m.row.chain).append("MANDATE_RELINQUISHED", id, payload, id);
      const after = await this.load(id, agent_code);
      if (!after) throw new ConsentStateUnknown(id, "мандат после отказа агента не читается");
      return this.toMandate(id, after.head, after.subj, after.status);
    });
  }

  private async statusAfterWrite(id: string, agent_code: string): Promise<MandateStatus> {
    const after = await this.load(id, agent_code);
    if (!after) throw new ConsentStateUnknown(id, "мандат после записи не читается");
    return after.status;
  }

  /**
   * Экран мандата для банка (стенд — эмулятор эмитента; ПИ-8 — PS-20): хэш записи и предмет. Неизвестный — undefined.
   * Предмет раскрывается: в боевом контуре — только аутентифицированному участнику (PS-20), никогда агенту (A7 п. 9.2).
   */
  async signingView(id: string): Promise<MandateSigningView | undefined> {
    const row = await this.store.getMandate(id);
    const m = row && (await this.load(id, row.agent_code));
    if (!m) return undefined;
    const t = m.head.payload as MandateRequestedPayload;
    return {
      id,
      hash: m.head.hash,
      status: m.status,
      principal_ref: t.principal_ref,
      amount_limit: t.amount_limit,
      currency: t.currency,
      valid_to: t.valid_to,
      subject: m.subj.subject,
      cart: m.subj.cart,
    };
  }

  /**
   * Проверка мандата этого агента без предмета (A7 п. 9.2, РП38 п. 6): ровно {outcome, amount_left, valid_to, as_of}.
   * Статус — свёрткой load (у CART — вместе с родителем, РП35 п. 2). Чужой или неизвестный — undefined.
   * До П3 (PS-09) amount_left = amount_limit у ACTIVE (расходования нет), 0 у остальных; STATE_UNKNOWN — с П3.
   */
  async verify(id: string, agent_code: string): Promise<MandateVerify | undefined> {
    const m = await this.load(id, agent_code);
    if (!m) return undefined;
    const t = m.head.payload as MandateRequestedPayload;
    const confirmed = m.status === "ACTIVE";
    return {
      outcome: confirmed ? "CONFIRMED" : "OUT_OF_SCOPE",
      amount_left: confirmed ? t.amount_limit : 0,
      valid_to: t.valid_to,
      as_of: this.now().toISOString(),
    };
  }

  /**
   * Выписка по мандату этого агента (A7 п. 9.3, РП38 п. 7): mandate_chain (у CART — родитель и CART) и records — вся
   * цепочка журнала, по ней хэши, Mandate.hash и подписи банка проверяются без Платформы. Соли предмета нет (только
   * обязательство в записи) — раскрытие предмета только клиенту через банк. Нарушенная цепочка или предмет не сходится
   * с обязательством — integrity BROKEN с пустыми массивами; неопределимый статус при цельной цепочке — исключение (503).
   */
  async evidence(id: string, agent_code: string): Promise<EvidenceV14 | undefined> {
    const row = await this.store.getMandate(id);
    if (!row || row.agent_code !== agent_code) return undefined;
    // Один снимок цепочки (РП35): проверка хэшей, статусы мандата и родителя и records — по одному и тому же массиву.
    let entries: readonly JournalEntry[];
    let m: LoadedMandate | undefined;
    let parent: LoadedMandate | undefined;
    try {
      entries = await this.snapshot(id, row.chain);
      m = await this.loadFrom(row, entries, agent_code);
      const parentRow = m?.head.parent_ref ? await this.store.getMandate(m.head.parent_ref) : undefined;
      if (m?.head.parent_ref) {
        parent = parentRow && (await this.loadFrom(parentRow, entries, agent_code));
        if (!parent) throw new ConsentIntegrityError(id, "родитель CART не читается");
      }
    } catch (err) {
      if (!(err instanceof ConsentIntegrityError)) throw err;
      return { mandate_chain: [], records: [], operations: [], integrity: "BROKEN" };
    }
    if (!m) return undefined;
    const chain = parent ? [parent, m] : [m];
    return {
      mandate_chain: chain.map((x) => this.toMandate(x.row.id, x.head, x.subj, x.status)),
      records: entries.map(({ seq, kind, ref, parent_ref, at, payload, prev_hash, hash }) => ({
        seq,
        kind,
        ref,
        parent_ref,
        at,
        payload,
        prev_hash,
        hash,
      })),
      operations: [],
      integrity: "OK",
    };
  }

  /**
   * Мандат этого агента со статусом на момент чтения. Чужой или неизвестный id — undefined (как неизвестный).
   * Цепочка проверяется целиком, предмет — по обязательству: расхождение — ConsentIntegrityError (инвариант 6).
   */
  async get(id: string, agent_code: string): Promise<Mandate | undefined> {
    const m = await this.load(id, agent_code);
    return m && this.toMandate(id, m.head, m.subj, m.status);
  }

  private async load(id: string, agent_code: string): Promise<LoadedMandate | undefined> {
    const row = await this.store.getMandate(id);
    if (!row || row.agent_code !== agent_code) return undefined;
    return this.loadFrom(row, await this.snapshot(id, row.chain), agent_code);
  }

  /**
   * Снимок цепочки — одно чтение, хэши проверены по этому же массиву (как verify() ядра: от начала цепочки, entryHash,
   * связи prev_hash). Записи, добавленные после чтения, в снимок не входят непроверенными (`/audit` К2.3 № 3, К2.6 № 1).
   */
  private async snapshot(id: string, chain: string): Promise<readonly JournalEntry[]> {
    const store = this.store.journal(chain);
    // Копия: хранилище в памяти отдаёт живой массив — запись, добавленная после чтения, в проверенный снимок не попадает.
    const entries = [...(await store.all())];
    let prev = store.genesis ?? GENESIS_HASH;
    for (const e of entries) {
      const { hash, ...rest } = e;
      if (e.prev_hash !== prev || entryHash(rest) !== hash) throw new ConsentIntegrityError(id, `цепочка ${chain} нарушена на seq ${e.seq}`);
      prev = hash;
    }
    return entries;
  }

  /** Мандат по снимку цепочки: статус мандата и, у CART, статус родителя — по одним и тем же записям (РП35). */
  private async loadFrom(row: MandateIndexRow, entries: readonly JournalEntry[], agent_code: string): Promise<LoadedMandate | undefined> {
    const id = row.id;
    if (row.agent_code !== agent_code) return undefined;
    const head = entries.find((e) => e.ref === id && e.kind === "MANDATE_REQUESTED");
    // Индекс без записи журнала — запись не завершилась: мандата нет.
    if (!head) return undefined;
    const payload = head.payload as MandateRequestedPayload;
    if (payload.agent_code !== agent_code) throw new ConsentIntegrityError(id, "agent_code записи ≠ индекса");
    const s = await this.store.getSubject(id);
    if (!s) throw new ConsentIntegrityError(id, "нет предмета");
    let subj: MandateSubject;
    try {
      subj = JSON.parse(s.subject_json) as MandateSubject;
    } catch {
      throw new ConsentIntegrityError(id, "предмет не читается");
    }
    if (subjectCommitment(s.salt, subj) !== payload.subject_commitment) {
      throw new ConsentIntegrityError(id, "предмет не совпадает с обязательством");
    }
    // После проверок целостности. Без порядка отзыва мандат недействителен (A7 п. 2.2, РП37): запись до РП37 не читается как действующая.
    if (typeof payload.revocation_order !== "string" || payload.revocation_order === "") {
      throw new ConsentStateUnknown(id, "нет порядка отзыва в записи (РП37)");
    }
    const now = this.now();
    const own = deriveStatus(id, entries, now);
    // CART под INTENT — статус вместе с родителем, одним проходом по той же цепочке (РП35).
    if (!head.parent_ref) return { row, head, subj, status: own };
    const parent = deriveStatus(head.parent_ref, entries, now);
    return { row, head, subj, status: withParentStatus(own, parent) };
  }

  private toMandate(id: string, head: JournalEntry, subj: MandateSubject, status: MandateStatus): Mandate {
    const { subject_commitment: _c, ...terms } = head.payload as MandateRequestedPayload;
    void _c;
    return {
      ...terms,
      subject: subj.subject,
      ...(subj.cart !== null ? { cart: subj.cart } : {}),
      id,
      status,
      created_at: head.at,
      hash: head.hash,
      prev_hash: head.prev_hash,
    };
  }
}

/** Отзыв и отказ пишутся только пока полномочия есть или ожидаются (РП38 п. 4). */
const revocable = (status: MandateStatus): boolean => status === "PENDING_SIGNATURE" || status === "ACTIVE";

/** Реквизиты записи и повтора совпадают: сравнение канонических строк без обязательства предмета. */
function sameTerms(recorded: MandateRequestedPayload, terms: MandateTerms): boolean {
  const { subject_commitment: _c, ...rest } = recorded;
  void _c;
  return canonicalJson(rest) === canonicalJson(terms);
}

/** Хэш реквизитов перечня для индекса (РП33 доп. п. 7): реквизиты открыты и в записи журнала, предмета в них нет. */
const termsHash = (terms: MandateTerms): string => sha256Hex(canonicalJson(terms));

/**
 * Усиленная подпись обязательна (A7 п. 3.2): предельная сумма выше qualified_signature_above_kop или срок от записи
 * мандата до valid_to дольше qualified_signature_above_days; порог — в копейках рублей, другая валюта — всегда.
 */
function needsQualified(t: MandateRequestedPayload, recordedAt: string, policy: SignaturePolicy): boolean {
  if (t.currency !== THRESHOLD_CURRENCY) return true;
  if (t.amount_limit > policy.qualified_signature_above_kop) return true;
  const days = (Date.parse(t.valid_to) - Date.parse(recordedAt)) / DAY_MS;
  return !(days <= policy.qualified_signature_above_days);
}
