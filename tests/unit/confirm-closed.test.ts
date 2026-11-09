// Закрытие запроса подтверждения Платформой после отзыва мандата — хранилище П6 в памяти (РП76 п. 2–4): pendingByAgent и
// closeRevoked; REJECTED без решения банка, closed {MANDATE_REVOKED, now}, событие confirmation.rejected той же записью.
// То же на PostgreSQL — tests/unit/confirm-closed-pg.test.ts (CI).
import { describe, expect, it } from "vitest";
import { MemoryConfirmationStore, newConfirmationId, newConfirmationRef, totalsHash, type ConfirmationRecord } from "../../src/confirm/index.js";
import { MemoryConsentStore } from "../../src/consent/store.js";

const AGENT = "nspk:agent:cnf-closed:v1";
const AT = "2026-11-09T10:00:00.000Z";
const NOW = "2026-11-09T10:05:00.000Z";
const EXPIRES = "2026-11-09T10:15:00.000Z";

const pending = (order_ref: string, over: Partial<ConfirmationRecord> = {}): ConfirmationRecord => ({
  confirmation_id: newConfirmationId(),
  agent_code: AGENT,
  mandate_id: "mnd_00000000-0000-4000-8000-000000000775",
  merchant_id: "MER-1042",
  amount: 340_000,
  currency: "RUB",
  order_ref,
  split_detected: false,
  status: "PENDING",
  created_at: AT,
  expires_at: EXPIRES,
  confirmation_ref: null,
  decision: null,
  op_ref: null,
  ...over,
});

const decision = (r: ConfirmationRecord, d: "APPROVE" | "REJECT") => ({
  participant_code: "bank:mem",
  kid: "kid-mem",
  decision: d,
  totals_hash: totalsHash(r),
  decided_at: AT,
  signature: "s".repeat(86),
});

function setup() {
  const events = new MemoryConsentStore();
  const store = new MemoryConfirmationStore({ events });
  const feed = async () => (await events.listEvents(AGENT, undefined, 100)).map((e) => [e.type, e.data]);
  return { store, feed };
}

describe("П6 в памяти: closeRevoked и pendingByAgent (РП76)", () => {
  it("PENDING → REJECTED с closed, без решения и ссылки; итоговые значения прежние; событие confirmation.rejected", async () => {
    const { store, feed } = setup();
    const r = await store.create(pending("ORD-1"));
    const done = await store.closeRevoked(r.confirmation_id, NOW);
    expect(done).toEqual({ ...r, status: "REJECTED", closed: { reason: "MANDATE_REVOKED", at: NOW } });
    expect(await store.get(r.confirmation_id)).toEqual(done);
    expect(await feed()).toEqual([
      ["confirmation.required", { confirmation_id: r.confirmation_id }],
      ["confirmation.rejected", { confirmation_id: r.confirmation_id }],
    ]);
  });

  it("повтор, APPROVED, REJECTED банком, срок вышел, неизвестный — undefined, запись и лента не меняются", async () => {
    const { store, feed } = setup();
    const r = await store.create(pending("ORD-2"));
    await store.closeRevoked(r.confirmation_id, NOW);
    expect(await store.closeRevoked(r.confirmation_id, NOW)).toBeUndefined();
    const a = await store.create(pending("ORD-3"));
    await store.decide(a.confirmation_id, decision(a, "APPROVE"), newConfirmationRef(), AT);
    const b = await store.create(pending("ORD-4"));
    await store.decide(b.confirmation_id, decision(b, "REJECT"), null, AT);
    const late = await store.create(pending("ORD-5"));
    const before = await feed();
    for (const id of [a.confirmation_id, b.confirmation_id, late.confirmation_id]) {
      const was = await store.get(id);
      expect(await store.closeRevoked(id, id === late.confirmation_id ? EXPIRES : NOW)).toBeUndefined();
      expect(await store.get(id)).toEqual(was);
    }
    expect(await store.closeRevoked(newConfirmationId(), NOW)).toBeUndefined();
    expect(await feed()).toEqual(before);
    expect((await store.get(b.confirmation_id))?.closed, "отказ банком — без closed").toBeUndefined();
  });

  it("pendingByAgent — только PENDING этого агента до срока", async () => {
    const { store } = setup();
    const a = await store.create(pending("ORD-6"));
    const b = await store.create(pending("ORD-7"));
    await store.create(pending("ORD-8", { expires_at: NOW }));
    await store.create(pending("ORD-9", { agent_code: "nspk:agent:other:v1" }));
    await store.decide(b.confirmation_id, decision(b, "APPROVE"), newConfirmationRef(), AT);
    expect((await store.pendingByAgent(AGENT, NOW)).map((x) => x.confirmation_id)).toEqual([a.confirmation_id]);
  });
});
