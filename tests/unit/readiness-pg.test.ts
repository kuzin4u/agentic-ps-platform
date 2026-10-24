// Знак готовности на PostgreSQL (PS-30 ч. 2 К1, РП57 п. 2; инвариант 6): только вставка — UPDATE, DELETE, TRUNCATE
// отвергает триггер; порядок — seq (bigserial), а не issued_at и не часы экземпляра; статус в два шага с двух экземпляров;
// повтор и конфликт ссылки — по UNIQUE (participant_code, readiness_ref). В CI (РП30 п. 7); локально без базы — пропуск.
import { generateKeyPairSync, randomUUID, sign as edSign } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { PgReadinessStore, type StoredAcquirerReadiness } from "../../src/participants/readiness.js";
import { participantReadinessSigningInput, TrustedParticipants, type ReadinessSignedRecord } from "../../src/participants/trusted.js";
import { jwkThumbprint } from "../../src/registry/keys.js";
import { buildServer } from "../../src/server.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const T = new Date("2026-10-24T10:00:00Z");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 };

const row = (merchant_id: string, ref: string, status: "ACTIVE" | "WITHDRAWN", issued_at = T): StoredAcquirerReadiness => ({
  participant_code: "acq:pg",
  kid: "kid-pg",
  merchant_id,
  readiness_ref: ref,
  status,
  issued_at: issued_at.toISOString(),
  signature: "s".repeat(86),
  received_at: T.toISOString(),
});

describe.skipIf(!DATABASE_URL)("PostgreSQL: знак готовности (РП57 п. 2)", () => {
  let db: TestDb;
  let one: PgReadinessStore;
  let two: PgReadinessStore;

  beforeAll(async () => {
    db = await openTestDb("readiness");
    one = new PgReadinessStore(db.pool);
    two = new PgReadinessStore(db.reopen());
  });
  afterAll(async () => {
    await db?.close();
  });

  it("таблица, индекс и триггеры — в своей схеме (current_schema())", async () => {
    const idx = await db.pool.query(
      "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename = 'merchant_readiness' AND indexname = 'merchant_readiness_last'",
    );
    expect(idx.rows).toHaveLength(1);
    const trg = await db.pool.query<{ tgname: string }>(
      `SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relname = 'merchant_readiness' AND NOT t.tgisinternal ORDER BY 1`,
    );
    expect(trg.rows.map((r) => r.tgname)).toEqual(["merchant_readiness_guard", "merchant_readiness_no_truncate"]);
  });

  it("только вставка: UPDATE, DELETE и TRUNCATE отвергаются; запись эквайрера без подписи и SUSPENDED без причины — CHECK", async () => {
    expect(await one.putAcquirer(row("MER-T", "t-1", "ACTIVE"))).toBe("inserted");
    await expect(db.pool.query("UPDATE merchant_readiness SET status = 'WITHDRAWN' WHERE merchant_id = 'MER-T'")).rejects.toThrow(/только вставка/);
    await expect(db.pool.query("DELETE FROM merchant_readiness WHERE merchant_id = 'MER-T'")).rejects.toThrow(/только вставка/);
    await expect(db.pool.query("TRUNCATE merchant_readiness")).rejects.toThrow(/только вставка/);
    await expect(
      db.pool.query(
        "INSERT INTO merchant_readiness (merchant_id, source, status, participant_code, kid, readiness_ref, issued_at, received_at) VALUES ('MER-T', 'ACQUIRER', 'ACTIVE', 'acq:pg', 'k', 'no-sig', 'x', 'x')",
      ),
    ).rejects.toThrow(/check/i);
    await expect(
      db.pool.query(
        "INSERT INTO merchant_readiness (merchant_id, source, status, participant_code, kid, readiness_ref, issued_at, signature, received_at) VALUES ('MER-T', 'ACQUIRER', 'ACTIVE', 'acq:pg', 'k', 'bad-sig', 'x', 'x', 'x')",
      ),
    ).rejects.toThrow(/check/i);
    await expect(
      db.pool.query("INSERT INTO merchant_readiness (merchant_id, source, status, received_at) VALUES ('MER-T', 'OPERATOR', 'SUSPENDED', 'x')"),
    ).rejects.toThrow(/check/i);
    expect((await one.current("MER-T")).status).toBe("ACTIVE");
  });

  it("порядок — seq, а не issued_at: поздняя по времени запись, вставленная раньше, не действует", async () => {
    expect(await one.putAcquirer(row("MER-O", "o-1", "WITHDRAWN", new Date(T.getTime() + 3_600_000)))).toBe("inserted");
    expect(await two.putAcquirer(row("MER-O", "o-2", "ACTIVE", new Date(T.getTime() - 3_600_000)))).toBe("inserted");
    expect((await one.current("MER-O")).status).toBe("ACTIVE");
    const seqs = await db.pool.query<{ readiness_ref: string; seq: string }>(
      "SELECT readiness_ref, seq FROM merchant_readiness WHERE merchant_id = 'MER-O' ORDER BY seq",
    );
    expect(seqs.rows.map((r) => r.readiness_ref)).toEqual(["o-1", "o-2"]);
  });

  it("два экземпляра: приостановление на одном — подача на другом 409 suspended; повтор той же записи — replayed и при SUSPENDED; другая запись под ссылкой — conflict", async () => {
    expect(await one.putAcquirer(row("MER-S", "s-1", "ACTIVE"))).toBe("inserted");
    await two.putOperator({ merchant_id: "MER-S", action: "SUSPENDED", reason: "DISCREPANCY", received_at: T.toISOString() });
    expect(await one.putAcquirer(row("MER-S", "s-2", "WITHDRAWN"))).toBe("suspended");
    expect(await one.putAcquirer(row("MER-S", "s-3", "ACTIVE"))).toBe("suspended");
    expect(await two.putAcquirer(row("MER-S", "s-1", "ACTIVE"))).toBe("replayed");
    expect(await two.putAcquirer(row("MER-S", "s-1", "WITHDRAWN"))).toBe("conflict");
    expect(await one.current("MER-S")).toEqual({ merchant_id: "MER-S", status: "SUSPENDED", since: T.toISOString(), reason: "DISCREPANCY" });
    // Запись эквайрера в обход проверки (гонка) — статус не меняет (РП57 п. 2, шаг 1).
    await db.pool.query(
      "INSERT INTO merchant_readiness (merchant_id, source, status, participant_code, kid, readiness_ref, issued_at, signature, received_at) VALUES ('MER-S', 'ACQUIRER', 'WITHDRAWN', 'acq:pg', 'k', 'raced', 'x', $1, 'x')",
      ["s".repeat(86)],
    );
    expect((await two.current("MER-S")).status).toBe("SUSPENDED");
    await one.putOperator({ merchant_id: "MER-S", action: "REINSTATED", reason: null, received_at: T.toISOString() });
    expect((await two.current("MER-S")).status, "после снятия — последняя запись эквайрера (raced WITHDRAWN)").toBe("NONE");
  });

  it("одновременно: приостановление на одном экземпляре и подача ACTIVE / WITHDRAWN на другом — итог всегда SUSPENDED (ревью КТ1 № 9)", async () => {
    for (let i = 0; i < 20; i++) {
      const m = `MER-R${i}`;
      expect(await one.putAcquirer(row(m, `rr-${i}-0`, "ACTIVE"))).toBe("inserted");
      const [put] = await Promise.all([
        two.putAcquirer(row(m, `rr-${i}-1`, i % 2 ? "ACTIVE" : "WITHDRAWN")),
        one.putOperator({ merchant_id: m, action: "SUSPENDED", reason: "AGENT_REFUSALS", received_at: T.toISOString() }),
      ]);
      expect(["inserted", "suspended"]).toContain(put);
      expect((await two.current(m)).status, `${m}: подача — ${put}`).toBe("SUSPENDED");
    }
  });

  it("одновременные подачи с двух экземпляров — обе записи, порядок по seq, статус — по последней", async () => {
    const refs = Array.from({ length: 10 }, (_, i) => `c-${i}`);
    const results = await Promise.all(refs.map((ref, i) => (i % 2 ? one : two).putAcquirer(row("MER-C", ref, i === 9 ? "WITHDRAWN" : "ACTIVE"))));
    expect(results.every((r) => r === "inserted")).toBe(true);
    const last = await db.pool.query<{ status: string }>("SELECT status FROM merchant_readiness WHERE merchant_id = 'MER-C' ORDER BY seq DESC LIMIT 1");
    expect((await one.current("MER-C")).status).toBe(last.rows[0]!.status === "ACTIVE" ? "ACTIVE" : "NONE");
    expect((await one.current("MER-UNKNOWN")).since).toBeNull();
  });

  it("ПИ-8 на двух экземплярах сервера: подача на одном видна на другом; повтор после WITHDRAWN статус не возвращает", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const { crv, kty, x } = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
    const kid = jwkThumbprint({ crv, kty, x });
    const trusted = new TrustedParticipants([{ participant_code: "acq:srv", kid, alg: "ed25519", public_key, role: "ACQUIRER", merchants: ["MER-SRV"] }], {
      stand: false,
    });
    const app = (store: PgReadinessStore) =>
      buildServer({
        env: "dev",
        participants: {
          trusted,
          consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1", now: () => T }),
          params: POLICY,
          now: () => T,
          readiness: { store, skewSec: 300 },
        },
      });
    const a1 = app(one);
    const a2 = app(two);
    const body = (status: "ACTIVE" | "WITHDRAWN", readiness_ref: string) => {
      const r: ReadinessSignedRecord = { participant_code: "acq:srv", kid, merchant_id: "MER-SRV", readiness_ref, status, issued_at: T.toISOString() };
      const { merchant_id: _m, ...rest } = r;
      void _m;
      return { ...rest, signature: edSign(null, participantReadinessSigningInput(r), privateKey).toString("base64url") };
    };
    try {
      const old = body("ACTIVE", `r-${randomUUID()}`);
      expect((await a1.inject({ method: "POST", url: "/participants/v1/merchants/MER-SRV/readiness", payload: old })).json().status).toBe("ACTIVE");
      const w = await a2.inject({ method: "POST", url: "/participants/v1/merchants/MER-SRV/readiness", payload: body("WITHDRAWN", `r-${randomUUID()}`) });
      expect(w.json().status).toBe("NONE");
      const replay = await a1.inject({ method: "POST", url: "/participants/v1/merchants/MER-SRV/readiness", payload: old });
      expect([replay.statusCode, replay.json().status]).toEqual([200, "NONE"]);
    } finally {
      await a1.close();
      await a2.close();
    }
  });
});
