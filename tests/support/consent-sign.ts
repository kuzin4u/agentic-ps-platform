// Подпись мандата в обход ПИ-8 для тестов П2 и ПАО (РП46 (а) п. 2): запись MANDATE_SIGNED с участником и строка SIGN
// порядка пары — тем же путём хранилища, что подпись банка (journalWithEvent с PairSign). Без строки SIGN подписанный
// мандат не читается (РП46 (а) п. 6, fail-closed).
import { AsyncHashChainJournal, type JournalEntry } from "@kuzin4u/agentic-core";
import type { ConsentStore } from "../../src/consent/store.js";

export const TEST_PARTICIPANT = "bank:test";

export async function signDirect(store: ConsentStore, id: string, at = new Date("2026-10-19T10:00:00Z")): Promise<void> {
  const row = (await store.getMandate(id))!;
  const entries: readonly JournalEntry[] = await store.journal(row.chain).all();
  const head = entries.find((e) => e.ref === id && e.kind === "MANDATE_REQUESTED");
  // Индекс без записи мандата (тест «родителя нет») — только MANDATE_SIGNED, пары нет.
  if (!head) {
    await new AsyncHashChainJournal(store.journal(row.chain), () => at.toISOString()).append("MANDATE_SIGNED", id, { participant_code: TEST_PARTICIPANT }, id);
    return;
  }
  const root_id = head.parent_ref ?? id;
  const root = entries.find((e) => e.ref === root_id && e.kind === "MANDATE_REQUESTED")!;
  const principal_ref = (root.payload as { principal_ref: string }).principal_ref;
  const sign = { pair: { participant_code: TEST_PARTICIPANT, principal_ref }, mandate_id: id, root_id, at: at.toISOString() };
  const draft = { agent_code: row.agent_code, type: "mandate.signed" as const, data: { mandate_id: id } };
  await new AsyncHashChainJournal(store.journalWithEvent(row.chain, draft, sign), () => at.toISOString()).append(
    "MANDATE_SIGNED",
    id,
    { participant_code: TEST_PARTICIPANT },
    id,
  );
}
