// События confirmation.* в памяти (PS-19 ч. 2, РП51 п. 1–5): переход запроса подтверждения П6 и событие агенту — в одном
// шаге; на переход — одно событие, у проигравшего условную запись события нет; data — только {confirmation_id};
// номер ленты — общий у агента; push — по подписке на момент записи; сбой события оставляет запрос без перехода.
import { describe, expect, it } from "vitest";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { MemoryConfirmationStore, newConfirmationId, newConfirmationRef, totalsHash, type ConfirmationRecord } from "../../src/confirm/index.js";
import { confirmationEventIdFor, eventIdFor, EVENT_ID } from "../../src/pao/events.js";

const AGENT = "nspk:agent:cnf-events:v1";
const OTHER = "nspk:agent:cnf-other:v1";
const AT = "2026-10-22T10:00:00.000Z";
const EXPIRES = "2026-10-22T10:15:00.000Z";
const M = "mnd_00000000-0000-4000-8000-000000000001";

const pending = (order_ref: string, agent_code = AGENT): ConfirmationRecord => ({
  confirmation_id: newConfirmationId(),
  agent_code,
  mandate_id: M,
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
});

const decision = (r: ConfirmationRecord, d: "APPROVE" | "REJECT") => ({
  participant_code: "bank:test",
  kid: "kid-test",
  decision: d,
  totals_hash: totalsHash(r),
  decided_at: AT,
  signature: "s".repeat(86),
});

function setup(pushFor?: (code: string, type: string) => boolean) {
  const events = new MemoryConsentStore();
  const store = new MemoryConfirmationStore({ events, ...(pushFor ? { pushFor } : {}) });
  const feed = async (code = AGENT) => events.listEvents(code, undefined, 100);
  return { events, store, feed };
}

describe("события confirmation.* в памяти (РП51 п. 1–5)", () => {
  it("каждый переход — одно событие: required → approved; data — ровно {confirmation_id}; event_id — от запроса и типа", async () => {
    const { store, feed } = setup();
    const r = await store.create(pending("ORD-1"));
    const ref = newConfirmationRef();
    expect((await store.decide(r.confirmation_id, decision(r, "APPROVE"), ref, "2026-10-22T10:01:00.000Z"))?.status).toBe("APPROVED");
    const evs = await feed();
    expect(evs.map((e) => [e.seq, e.type, e.at])).toEqual([
      [1, "confirmation.required", AT],
      [2, "confirmation.approved", "2026-10-22T10:01:00.000Z"],
    ]);
    for (const e of evs) {
      expect(e.data).toEqual({ confirmation_id: r.confirmation_id });
      expect(e.event_id).toMatch(EVENT_ID);
      expect(e).toMatchObject({ journal_chain: null, journal_seq: null });
    }
    expect(evs[0]!.event_id).toBe(confirmationEventIdFor(r.confirmation_id, "confirmation.required"));
    expect(evs[1]!.event_id).toBe(confirmationEventIdFor(r.confirmation_id, "confirmation.approved"));
    // Погашение своего события не даёт (РП51 п. 2).
    expect(await store.consume(ref, "OPKC-1", "2026-10-22T10:02:00.000Z")).toBe(true);
    expect(await feed()).toHaveLength(2);
  });

  it("своя метка event_id: событие запроса не совпадает с событием записи журнала", () => {
    const id = newConfirmationId();
    expect(confirmationEventIdFor(id, "confirmation.required")).not.toBe(confirmationEventIdFor(id, "confirmation.expired"));
    expect(confirmationEventIdFor(id, "confirmation.required")).not.toBe(eventIdFor(id, 1));
  });

  it("REJECT — confirmation.rejected; истечение — confirmation.expired с моментом обращения", async () => {
    const { store, feed } = setup();
    const a = await store.create(pending("ORD-rej"));
    await store.decide(a.confirmation_id, decision(a, "REJECT"), null, "2026-10-22T10:01:00.000Z");
    const b = await store.create(pending("ORD-exp"));
    expect(await store.expire(b.confirmation_id, "2026-10-22T10:14:59.999Z"), "до срока").toBe(false);
    expect(await store.expire(b.confirmation_id, "2026-10-22T10:20:00.000Z")).toBe(true);
    expect((await feed()).map((e) => [e.type, e.at])).toEqual([
      ["confirmation.required", AT],
      ["confirmation.rejected", "2026-10-22T10:01:00.000Z"],
      ["confirmation.required", AT],
      ["confirmation.expired", "2026-10-22T10:20:00.000Z"],
    ]);
  });

  it("без перехода — без события: тот же ключ, второе решение, решение после срока, повторное истечение", async () => {
    const { store, feed } = setup();
    const r = await store.create(pending("ORD-dup"));
    expect((await store.create(pending("ORD-dup"))).confirmation_id, "прежний запрос").toBe(r.confirmation_id);
    await store.decide(r.confirmation_id, decision(r, "APPROVE"), newConfirmationRef(), AT);
    expect(await store.decide(r.confirmation_id, decision(r, "REJECT"), null, AT)).toBeUndefined();
    const late = await store.create(pending("ORD-late"));
    expect(await store.decide(late.confirmation_id, decision(late, "APPROVE"), newConfirmationRef(), EXPIRES)).toBeUndefined();
    expect(await store.expire(late.confirmation_id, EXPIRES)).toBe(true);
    expect(await store.expire(late.confirmation_id, EXPIRES)).toBe(false);
    expect((await feed()).map((e) => e.type)).toEqual(["confirmation.required", "confirmation.approved", "confirmation.required", "confirmation.expired"]);
  });

  it("событие получает агент записи; чужому агенту не видно", async () => {
    const { store, feed } = setup();
    await store.create(pending("ORD-own"));
    await store.create(pending("ORD-other", OTHER));
    expect((await feed()).map((e) => e.seq)).toEqual([1]);
    expect((await feed(OTHER)).map((e) => e.seq)).toEqual([1]);
    expect((await feed(OTHER))[0]!.data).not.toEqual((await feed())[0]!.data);
  });

  it("push — строка попытки, если агент подписан на тип на момент записи (РП40 п. 5)", async () => {
    const { events, store, feed } = setup((_code, type) => type === "confirmation.required");
    const r = await store.create(pending("ORD-push"));
    await store.decide(r.confirmation_id, decision(r, "REJECT"), null, AT);
    const [req, rej] = await feed();
    expect((await events.delivery(req!.event_id))?.state).toBe("PENDING");
    expect(await events.delivery(rej!.event_id), "на rejected не подписан").toBeUndefined();
  });

  it("сбой записи события — переход не записан (откат вместе, РП51 п. 7)", async () => {
    const store = new MemoryConfirmationStore({
      events: {
        appendConfirmationEventNow: () => {
          throw new Error("лента недоступна");
        },
      },
    });
    const rec = pending("ORD-fail");
    await expect(store.create(rec)).rejects.toThrow(/лента/);
    expect(await store.get(rec.confirmation_id)).toBeUndefined();
  });
});
