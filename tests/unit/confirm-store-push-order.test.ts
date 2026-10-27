// Строка push в PG-хранилище подтверждения — до BEGIN (КТ1 PS-05в ч. 2б-1 № 2): реестр читается другим соединением того
// же пула, и внутри транзакции N одновременных переходов держали бы N соединений и ждали ещё N. Подставной пул без базы:
// порядок «push → connect» у create, expire и decide; повтор существующего запроса — без чтения реестра (№ 4).
import { describe, expect, it } from "vitest";
import { PgConfirmationStore, type ConfirmationRecord } from "../../src/confirm/index.js";
import type { TxSqlPool } from "../../src/consent/store.js";

const AGENT = "nspk:agent:cnf-order:v1";
const AT = "2026-10-27T10:00:00.000Z";
const EXPIRES = "2099-01-01T00:00:00.000Z";

const rec: ConfirmationRecord = {
  confirmation_id: "cnf_00000000-0000-4000-8000-000000000001",
  agent_code: AGENT,
  mandate_id: "mnd_00000000-0000-4000-8000-000000000001",
  merchant_id: "MER-1042",
  amount: 340_000,
  currency: "RUB",
  order_ref: "ord-1",
  split_detected: false,
  status: "PENDING",
  created_at: AT,
  expires_at: EXPIRES,
  confirmation_ref: null,
  decision: null,
  op_ref: null,
};

const row = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  ...rec,
  amount: String(rec.amount),
  participant_code: null,
  kid: null,
  totals_hash: null,
  decided_at: null,
  signature: null,
  instrument_chosen: null,
  ...over,
});

/** Пул: чтения вне транзакции и запросы транзакции пишутся в общий журнал шагов; existing — запрос по ключу уже есть. */
function fakePool(steps: string[], existing: boolean): TxSqlPool {
  let inserted = existing;
  const answer = async (text: string): Promise<{ rows: Record<string, unknown>[] }> => {
    if (/^SELECT .* FROM confirmations\s+WHERE mandate_id/s.test(text)) return { rows: inserted ? [row()] : [] };
    if (/^SELECT .* FROM confirmations\s+WHERE confirmation_id/s.test(text)) return { rows: [row()] };
    if (/^\s*INSERT INTO confirmations/.test(text)) {
      inserted = true;
      return { rows: [{ confirmation_id: rec.confirmation_id }] };
    }
    if (/^UPDATE confirmations SET status = 'EXPIRED'/.test(text)) return { rows: [row({ status: "EXPIRED" })] };
    if (/^UPDATE confirmations SET status = \$2/.test(text)) return { rows: [row({ status: "REJECTED" })] };
    if (/INSERT INTO pao_events/.test(text)) return { rows: [{ event_id: "evt" }] };
    return { rows: [] };
  };
  return {
    query: async <R extends Record<string, unknown>>(text: string) => (await answer(text)) as { rows: R[] },
    connect: async () => {
      steps.push("connect");
      return {
        query: async <R extends Record<string, unknown>>(text: string) => {
          steps.push(`tx:${text.trim().split(/\s+/)[0]}`);
          return (await answer(text)) as { rows: R[] };
        },
        release: () => {},
      };
    },
  };
}

const storeWith = (steps: string[], existing = false): PgConfirmationStore =>
  new PgConfirmationStore(fakePool(steps, existing), {
    lockTimeoutMs: 5_000,
    pushFor: async (agent_code, type) => {
      steps.push(`push:${type}`);
      expect(agent_code).toBe(AGENT);
      return true;
    },
  });

describe("PgConfirmationStore: строка push до BEGIN (КТ1 PS-05в ч. 2б-1 № 2)", () => {
  it("create, expire, decide — реестр читается до connect транзакции, не внутри неё", async () => {
    const created: string[] = [];
    await storeWith(created).create(rec);
    expect(created.slice(0, 2)).toEqual(["push:confirmation.required", "connect"]);

    const expired: string[] = [];
    expect(await storeWith(expired).expire(rec.confirmation_id, EXPIRES)).toBe(true);
    expect(expired.slice(0, 2)).toEqual(["push:confirmation.expired", "connect"]);

    const decided: string[] = [];
    const d = { participant_code: "bank:x", kid: "kid-x", decision: "REJECT" as const, totals_hash: "h", decided_at: AT, signature: "s" };
    expect(await storeWith(decided).decide(rec.confirmation_id, d, null, AT)).toBeDefined();
    expect(decided.slice(0, 2)).toEqual(["push:confirmation.rejected", "connect"]);
  });

  it("повтор существующего запроса — без чтения реестра и без транзакции, как в памяти (КТ1 ч. 2б-1 № 4)", async () => {
    const steps: string[] = [];
    expect((await storeWith(steps, true).create(rec)).confirmation_id).toBe(rec.confirmation_id);
    expect(steps).toEqual([]);
  });
});
