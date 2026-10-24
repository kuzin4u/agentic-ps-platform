// Метаданные пакета на PostgreSQL (PS-30 ч. 2 К2, РП57 п. 5; инвариант 6): только вставка — триггер; CHECK формы (aoi —
// ровно два строковых поля, подпись — base64url 64 байта); повтор и конфликт ссылки — по UNIQUE с двух экземпляров;
// последняя запись реквизита — по seq; реквизит продавца — по паре credential_ref + merchant_id. В CI; локально — пропуск.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgCredentialStore } from "../../src/credentials/store.js";
import { PgPaymentMetadataStore, type StoredPaymentMetadata } from "../../src/participants/payments.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const AT = "2026-10-24T10:00:00.000Z";
const rec = (ref: string, credential_ref: string, extra: Partial<StoredPaymentMetadata> = {}): StoredPaymentMetadata => ({
  participant_code: "acq:pg",
  kid: "kid-pg",
  merchant_id: "MER-1042",
  metadata_ref: ref,
  credential_ref,
  order_ref: "ORD-1",
  aoi: { agent_code: "nspk:agent:pg:v1", mandate_id: "mnd_pg" },
  submitted_at: AT,
  signature: "s".repeat(86),
  received_at: AT,
  ...extra,
});

describe.skipIf(!DATABASE_URL)("PostgreSQL: метаданные пакета (РП57 п. 5)", () => {
  let db: TestDb;
  let one: PgPaymentMetadataStore;
  let two: PgPaymentMetadataStore;

  beforeAll(async () => {
    db = await openTestDb("payments");
    one = new PgPaymentMetadataStore(db.pool);
    two = new PgPaymentMetadataStore(db.reopen());
  });
  afterAll(async () => {
    await db?.close();
  });

  it("таблица, индекс и триггеры — в своей схеме (current_schema())", async () => {
    const idx = await db.pool.query(
      "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename = 'payment_metadata' AND indexname = 'payment_metadata_last'",
    );
    expect(idx.rows).toHaveLength(1);
    const trg = await db.pool.query<{ tgname: string }>(
      `SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relname = 'payment_metadata' AND NOT t.tgisinternal ORDER BY 1`,
    );
    expect(trg.rows.map((r) => r.tgname)).toEqual(["payment_metadata_guard", "payment_metadata_no_truncate"]);
  });

  it("только вставка; CHECK: aoi с лишним полем или не строкой, подпись не по форме — отказ; без aoi — NULL", async () => {
    expect(await one.put(rec("t-1", "crd_t"))).toBe("inserted");
    await expect(db.pool.query("UPDATE payment_metadata SET order_ref = 'x'")).rejects.toThrow(/только вставка/);
    await expect(db.pool.query("DELETE FROM payment_metadata")).rejects.toThrow(/только вставка/);
    await expect(db.pool.query("TRUNCATE payment_metadata")).rejects.toThrow(/только вставка/);
    const raw = (aoi: string | null, signature = "s".repeat(86)) =>
      db.pool.query(
        `INSERT INTO payment_metadata (participant_code, kid, merchant_id, metadata_ref, credential_ref, order_ref, aoi, submitted_at, signature, received_at)
         VALUES ('acq:pg', 'k', 'MER-1042', $1, 'crd_raw', 'ORD-1', $2::jsonb, 'x', $3, 'x')`,
        [`raw-${Math.random().toString(36).slice(2, 10)}`, aoi, signature],
      );
    await expect(raw('{"agent_code":"a","mandate_id":"m","amount":1}')).rejects.toThrow(/check/i);
    await expect(raw('{"agent_code":"a","mandate_id":1}')).rejects.toThrow(/check/i);
    await expect(raw('{"agent_code":"a","mandate_id":"m"}', "x")).rejects.toThrow(/check/i);
    await raw(null);
    expect(await one.put(rec("t-2", "crd_noaoi", { aoi: undefined }))).toBe("inserted");
    expect((await two.latest("MER-1042", "crd_noaoi"))?.aoi).toBeUndefined();
  });

  it("два экземпляра: повтор той же записи — replayed, та же ссылка с другой записью — conflict; последняя — по seq", async () => {
    expect(await one.put(rec("r-1", "crd_r", { order_ref: "ORD-A", submitted_at: "2026-10-24T12:00:00.000Z" }))).toBe("inserted");
    expect(await two.put(rec("r-2", "crd_r", { order_ref: "ORD-B", submitted_at: "2026-10-24T08:00:00.000Z" }))).toBe("inserted");
    expect(await two.put(rec("r-1", "crd_r", { order_ref: "ORD-A", submitted_at: "2026-10-24T12:00:00.000Z" }))).toBe("replayed");
    expect(await one.put(rec("r-1", "crd_r", { order_ref: "ORD-C" }))).toBe("conflict");
    expect((await one.latest("MER-1042", "crd_r"))?.order_ref, "по seq, а не по submitted_at").toBe("ORD-B");
    const both = await Promise.all([one.put(rec("c-1", "crd_c")), two.put(rec("c-1", "crd_c"))]);
    expect(both.sort()).toEqual(["inserted", "replayed"]);
  });

  it("credentialForMerchant: реквизит по паре credential_ref + merchant_id; другой продавец — undefined", async () => {
    const store = new PgCredentialStore(db.pool);
    await store.putToken({
      token_ref: "tok_pm",
      agent_code: "nspk:agent:pg:v1",
      mandate_id: "mnd_pm",
      merchant_scope: ["MER-1042"],
      valid_to: AT,
      funding_ref: "fnd_pm",
      created_at: AT,
      merchant_mcc: { "MER-1042": ["5462"] },
    });
    await store.putCredential({
      credential_ref: "crd_pm",
      agent_code: "nspk:agent:pg:v1",
      mandate_id: "mnd_pm",
      token_ref: "tok_pm",
      order_ref: "ORD-PM",
      merchant_id: "MER-1042",
      amount_max: 1_000,
      currency: "RUB",
      valid_to: AT,
      cryptogram_sha256: "e".repeat(64),
      status: "ISSUED",
      op_ref: null,
      created_at: AT,
    });
    expect((await store.credentialForMerchant("crd_pm", "MER-1042"))?.order_ref).toBe("ORD-PM");
    expect(await store.credentialForMerchant("crd_pm", "MER-4401")).toBeUndefined();
    expect(await store.credentialForMerchant("crd_none", "MER-1042")).toBeUndefined();
  });
});
