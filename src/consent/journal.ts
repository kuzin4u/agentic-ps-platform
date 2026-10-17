// П2 Журнал согласий над журналом ядра (РП14): запрос мандата и чтение со статусом-свёрткой (PS-06 К1.2).
// Проверка запроса по схеме ПАО, идемпотентность и HTTP — К1.3; id от (агент, ключ) и повтор — К2.1 (РП33 доп.);
// подпись, отзыв, verify, выписка — часть 2.
import { AsyncHashChainJournal, canonicalJson, sha256Hex, type AsyncJournalStore, type JournalEntry } from "@kuzin4u/agentic-core";
import type { Mandate, MandateRequest } from "../shared/pao.js";
import {
  ConsentIntegrityError,
  ConsentKeyReused,
  consentChain,
  deriveStatus,
  mandateIdFor,
  newSalt,
  subjectCommitment,
  type MandateRequestedPayload,
  type MandateStatus,
  type MandateSubject,
  type MandateTerms,
} from "./model.js";
import { ConsentRowConflict, type ConsentStore, type MandateIndexRow } from "./store.js";
import { assertNarrows, ConsentRequestRejected, pickSubject, pickTerms } from "./terms.js";

export interface ConsentJournalOptions {
  readonly now?: () => Date;
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

  constructor(
    private readonly store: ConsentStore,
    opts: ConsentJournalOptions = {},
  ) {
    this.now = opts.now ?? (() => new Date());
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
    const terms = pickTerms(agent_code, req, now);
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
      terms = pickTerms(agent_code, req, null);
      subj = pickSubject(req, terms.amount_limit);
    } catch (err) {
      if (err instanceof ConsentRequestRejected) throw new ConsentKeyReused(row.id);
      throw err;
    }
    const m = await this.load(row.id, agent_code);
    if (m) {
      if (!sameTerms(m.head.payload as MandateRequestedPayload, terms) || canonicalJson(m.subj) !== canonicalJson(subj)) {
        throw new ConsentKeyReused(row.id);
      }
      return this.toMandate(row.id, m.head, m.subj, m.status);
    }
    const expectedChain = terms.parent_id ? (await this.store.getMandate(terms.parent_id))?.chain : consentChain(row.id);
    if (row.chain !== expectedChain || row.terms_hash !== termsHash(terms)) throw new ConsentKeyReused(row.id);
    const s = await this.store.getSubject(row.id);
    if (s && s.subject_json !== canonicalJson(subj)) throw new ConsentKeyReused(row.id);
    const fresh = pickTerms(agent_code, req, this.now());
    await this.chainFor(row.id, agent_code, fresh, subj);
    return this.complete(row.id, row.chain, fresh, subj, s?.salt, beforeWrite);
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
    // Статус — свёрткой и в ответе на запрос, как при чтении.
    return this.toMandate(id, entry, subj, deriveStatus(id, [entry], this.now()));
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
    const journal = this.chainJournal(row.chain);
    const check = await journal.verify();
    if (!check.ok) throw new ConsentIntegrityError(id, `цепочка ${row.chain} нарушена на seq ${check.brokenAt}`);
    const entries = await journal.extract(id);
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
    return { row, head, subj, status: deriveStatus(id, entries, this.now()) };
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

/** Реквизиты записи и повтора совпадают: сравнение канонических строк без обязательства предмета. */
function sameTerms(recorded: MandateRequestedPayload, terms: MandateTerms): boolean {
  const { subject_commitment: _c, ...rest } = recorded;
  void _c;
  return canonicalJson(rest) === canonicalJson(terms);
}

/** Хэш реквизитов перечня для индекса (РП33 доп. п. 7): реквизиты открыты и в записи журнала, предмета в них нет. */
const termsHash = (terms: MandateTerms): string => sha256Hex(canonicalJson(terms));
