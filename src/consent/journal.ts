// П2 Журнал согласий над журналом ядра (РП14): запрос мандата и чтение со статусом-свёрткой (PS-06 К1.2).
// Проверка запроса по схеме ПАО, идемпотентность и HTTP — К1.3; подпись, отзыв, verify, выписка — часть 2.
import { AsyncHashChainJournal, canonicalJson, type JournalEntry } from "@kuzin4u/agentic-core";
import type { Mandate, MandateRequest } from "../shared/pao.js";
import {
  ConsentIntegrityError,
  consentChain,
  deriveStatus,
  newMandateId,
  newSalt,
  subjectCommitment,
  type MandateRequestedPayload,
  type MandateStatus,
  type MandateSubject,
} from "./model.js";
import type { ConsentStore, MandateIndexRow } from "./store.js";
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

  private chainJournal(chain: string): AsyncHashChainJournal {
    return new AsyncHashChainJournal(this.store.journal(chain), () => this.now().toISOString());
  }

  /**
   * Запрос мандата агентом: запись MANDATE_REQUESTED, статус PENDING_SIGNATURE (подпись — у принципала в банке).
   * agent_code — из проверенного обращения, не из тела (инвариант 5). В запись — только поля перечня (terms.ts).
   * CART под INTENT — только под действующим (ACTIVE) родителем этого агента и только сужением (A7 п. 5).
   * Порядок: индекс, предмет, запись журнала; запись журнала — источник истины (store.ts).
   */
  async request(agent_code: string, req: MandateRequest): Promise<Mandate> {
    const now = this.now();
    const terms = pickTerms(agent_code, req, now);
    const subj = pickSubject(req, terms.amount_limit);
    const id = newMandateId();
    let chain = consentChain(id);
    if (terms.parent_id) {
      // Родитель — по журналу, как при чтении: индекс без записи, чужой агент — как неизвестный.
      const parent = await this.load(terms.parent_id, agent_code);
      if (!parent) throw new ConsentRequestRejected("PARENT_NOT_FOUND", "parent_id");
      if (parent.status !== "ACTIVE") throw new ConsentRequestRejected("PARENT_NOT_ACTIVE", "parent_id");
      assertNarrows(terms, subj, parent.head.payload as MandateRequestedPayload);
      chain = parent.row.chain;
    }
    const salt = newSalt();
    const payload: MandateRequestedPayload = { ...terms, subject_commitment: subjectCommitment(salt, subj) };
    await this.store.insertMandate({ id, chain, agent_code, created_at: now.toISOString() });
    await this.store.insertSubject({ mandate_id: id, salt, subject_json: canonicalJson(subj) });
    const entry = await this.chainJournal(chain).append("MANDATE_REQUESTED", id, payload, terms.parent_id ?? null);
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
