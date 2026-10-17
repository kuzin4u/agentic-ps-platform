// П2 Журнал согласий (PS-06 К1.2): запись мандата, статус — свёртка записей, обязательство предмета, только вставка.
// Одни и те же проверки — на памяти ядра (всегда) и на PostgreSQL (в CI, РП30 п. 7).
// Длинные цифровые строки — не номера карт: проверку Луна не проходят (инвариант 1, guard.py).
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AsyncHashChainJournal,
  canonicalJson,
  JournalAppendConflict,
  migrationsDir,
  type JournalEntry,
} from "@kuzin4u/agentic-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import {
  ConsentIntegrityError,
  ConsentStateUnknown,
  consentChain,
  deriveStatus,
  MANDATE_ID,
  subjectCommitment,
  type MandateRequestedPayload,
} from "../../src/consent/model.js";
import { ConsentRowConflict, MemoryConsentStore, PgConsentStore, type ConsentStore } from "../../src/consent/store.js";
import { ConsentRequestRejected, isOpaquePrincipalRef } from "../../src/consent/terms.js";
import { assertMigrationRanges, platformMigrationsDir } from "../../src/shared/migrations.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const A = "nspk:agent:consent-a:v1";
const B = "nspk:agent:consent-b:v1";
const T0 = new Date("2026-10-17T10:00:00Z");
/** 16 цифр подряд, не проходит проверку Луна. */
const DIGITS16 = "1234567812345678";

const intent = (over: Partial<MandateRequest> = {}): MandateRequest => ({
  type: "INTENT",
  subject: "молоко 2 л",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-10-24T10:00:00Z",
  merchant_scope: ["MER-1042", "MER-77"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
  ...over,
});

const cart = (parent_id: string, over: Partial<MandateRequest> = {}): MandateRequest =>
  intent({
    type: "CART",
    parent_id,
    subject: "корзина SHOP-1042",
    amount_limit: 12_900,
    merchant_scope: ["MER-1042"],
    cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }], total: 12_900 },
    ...over,
  });

/** Подпись принципала — часть 2 PS-06; здесь запись MANDATE_SIGNED пишется в цепочку напрямую. */
async function sign(store: ConsentStore, id: string): Promise<void> {
  const row = (await store.getMandate(id))!;
  await new AsyncHashChainJournal(store.journal(row.chain), () => T0.toISOString()).append(
    "MANDATE_SIGNED",
    `${id}:signed`,
    {},
    id,
  );
}

const rejected = (reason: string, field: string) =>
  expect.objectContaining({ reason, field }) as unknown as ConsentRequestRejected;

function suite(name: string, open: () => Promise<{ store: ConsentStore }>) {
  describe(name, () => {
    let store: ConsentStore;
    let now = T0;
    let journal: ConsentJournal;
    beforeAll(async () => {
      ({ store } = await open());
      journal = new ConsentJournal(store, { now: () => now });
    });

    const signedIntent = async (over: Partial<MandateRequest> = {}) => {
      const p = await journal.request(A, intent(over));
      await sign(store, p.id!);
      return p;
    };

    it("запрос INTENT: PENDING_SIGNATURE, id Платформы, agent_code — из обращения, хэш записи в ответе", async () => {
      now = T0;
      const m = await journal.request(A, { ...intent(), ...({ agent_code: B } as object) });
      expect(m.id).toMatch(MANDATE_ID);
      expect(m.status).toBe("PENDING_SIGNATURE");
      expect(m.agent_code).toBe(A);
      expect(m.subject).toBe("молоко 2 л");
      expect(m.created_at).toBe(T0.toISOString());
      expect(m.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(await journal.get(m.id!, A)).toEqual(m);
    });

    it("поля тела сверх перечня в запись и ответ не попадают (signature_type, status, pan, лишнее в conditional)", async () => {
      const body = {
        ...intent({ settlement_mode: "CONDITIONAL", conditional: { provider: "cx:nsvr", deal_ref: "deal-1" } }),
        signature_type: "qualified",
        status: "ACTIVE",
        id: "mnd_forged",
        hash: "f".repeat(64),
        pan: DIGITS16,
      } as MandateRequest;
      (body.conditional as Record<string, unknown>).phone = "+79990000000";
      const m = await journal.request(A, body);
      const entry = (await new AsyncHashChainJournal(store.journal(consentChain(m.id!))).extract(m.id!))[0]!;
      const p = entry.payload as Record<string, unknown>;
      expect(Object.keys(p).sort()).toEqual(
        [
          "agent_code",
          "amount_limit",
          "conditional",
          "currency",
          "merchant_scope",
          "mode",
          "parent_id",
          "principal_ref",
          "settlement_mode",
          "subject_commitment",
          "type",
          "valid_to",
        ].sort(),
      );
      expect(p.conditional).toEqual({ provider: "cx:nsvr", deal_ref: "deal-1" });
      const json = canonicalJson(p) + canonicalJson(await journal.get(m.id!, A));
      for (const leak of ["qualified", DIGITS16, "+79990000000", "mnd_forged"]) expect(json).not.toContain(leak);
      expect(m.status).toBe("PENDING_SIGNATURE");
      expect(m).not.toHaveProperty("signature_type");
    });

    it("предмет не раскрыт в журнале: в записи только subject_commitment, соль у одинаковых предметов разная", async () => {
      const m1 = await journal.request(A, intent());
      const m2 = await journal.request(A, intent());
      const e1 = (await new AsyncHashChainJournal(store.journal(consentChain(m1.id!))).extract(m1.id!))[0]!;
      const e2 = (await new AsyncHashChainJournal(store.journal(consentChain(m2.id!))).extract(m2.id!))[0]!;
      const p1 = e1.payload as MandateRequestedPayload;
      expect(canonicalJson(e1.payload)).not.toContain("молоко");
      expect(p1).not.toHaveProperty("subject");
      expect(p1).not.toHaveProperty("cart");
      expect(p1.merchant_scope).toEqual(["MER-1042", "MER-77"]);
      expect(p1.subject_commitment).toMatch(/^[0-9a-f]{64}$/);
      expect(p1.subject_commitment).not.toBe((e2.payload as MandateRequestedPayload).subject_commitment);
      const s = (await store.getSubject(m1.id!))!;
      expect(s.salt).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(subjectCommitment(s.salt, { subject: "молоко 2 л", cart: null })).toBe(p1.subject_commitment);
    });

    it("чужой и неизвестный id — undefined (как неизвестный)", async () => {
      const m = await journal.request(A, intent());
      expect(await journal.get(m.id!, B)).toBeUndefined();
      expect(await journal.get("mnd_00000000-0000-4000-8000-000000000000", A)).toBeUndefined();
    });

    it("CART под действующим INTENT — в цепочке родителя, статус родителя не меняется", async () => {
      const p = await signedIntent();
      const c = await journal.request(A, cart(p.id!));
      expect((await store.getMandate(c.id!))!.chain).toBe(consentChain(p.id!));
      expect(c.cart?.total).toBe(12_900);
      expect(c.status).toBe("PENDING_SIGNATURE");
      expect((await journal.get(p.id!, A))!.status).toBe("ACTIVE");
      expect((await journal.get(c.id!, A))!.parent_id).toBe(p.id);
    });

    it("CART: родитель чужой, без записи журнала, не подписан, сам CART — отказ, запись не пишется", async () => {
      const p = await signedIntent();
      await expect(journal.request(B, cart(p.id!))).rejects.toEqual(rejected("PARENT_NOT_FOUND", "parent_id"));
      const orphan = "mnd_44444444-4444-4444-8444-444444444444";
      await store.insertMandate({ id: orphan, chain: consentChain(orphan), agent_code: A, created_at: T0.toISOString() });
      await sign(store, orphan);
      await expect(journal.request(A, cart(orphan))).rejects.toEqual(rejected("PARENT_NOT_FOUND", "parent_id"));
      const pending = await journal.request(A, intent());
      await expect(journal.request(A, cart(pending.id!))).rejects.toEqual(rejected("PARENT_NOT_ACTIVE", "parent_id"));
      const c = await journal.request(A, cart(p.id!));
      await sign(store, c.id!);
      await expect(journal.request(A, cart(c.id!))).rejects.toEqual(rejected("PARENT_MISMATCH", "parent_id"));
      const before = (await store.journal(consentChain(p.id!)).all()).length;
      await expect(journal.request(A, cart(p.id!, { amount_limit: 60_000 }))).rejects.toBeInstanceOf(ConsentRequestRejected);
      expect((await store.journal(consentChain(p.id!)).all()).length).toBe(before);
    });

    it.each([
      ["сумма больше родителя", { amount_limit: 50_001 }, "SCOPE_WIDENED", "amount_limit"],
      ["срок позже родителя", { valid_to: "2026-10-24T10:00:01Z" }, "SCOPE_WIDENED", "valid_to"],
      ["область шире родителя", { merchant_scope: ["MER-1042", "MER-9"] }, "SCOPE_WIDENED", "merchant_scope"],
      [
        "продавец корзины вне области родителя",
        { cart: { merchant_id: "MER-9", items: [{ sku: "x", qty: 1, price: 1 }], total: 1 } },
        "SCOPE_WIDENED",
        "cart.merchant_id",
      ],
      ["другая валюта", { currency: "USD" }, "PARENT_MISMATCH", "currency"],
      ["другой принципал", { principal_ref: "prn_other" }, "PARENT_MISMATCH", "principal_ref"],
    ] as const)("CART: %s — отказ (A7 п. 5)", async (_n, over, reason, field) => {
      const p = await signedIntent();
      await expect(journal.request(A, cart(p.id!, over as Partial<MandateRequest>))).rejects.toEqual(rejected(reason, field));
    });

    it("наступил valid_to — EXPIRED без новой записи; valid_to в прошлом при запросе — отказ", async () => {
      now = T0;
      const m = await journal.request(A, intent());
      now = new Date("2026-10-24T10:00:00Z");
      expect((await journal.get(m.id!, A))!.status).toBe("EXPIRED");
      await expect(journal.request(A, intent())).rejects.toEqual(rejected("FIELD_INVALID", "valid_to"));
      now = T0;
    });

    it("индекс без записи журнала (запись не завершилась) — мандата нет", async () => {
      const id = "mnd_11111111-1111-4111-8111-111111111111";
      await store.insertMandate({ id, chain: consentChain(id), agent_code: A, created_at: T0.toISOString() });
      expect(await journal.get(id, A)).toBeUndefined();
    });

    it("повторная вставка в индекс и предмет — ConsentRowConflict, не перезапись", async () => {
      const m = await journal.request(A, intent());
      const row = (await store.getMandate(m.id!))!;
      await expect(store.insertMandate({ ...row, agent_code: B })).rejects.toBeInstanceOf(ConsentRowConflict);
      const s = (await store.getSubject(m.id!))!;
      await expect(store.insertSubject({ ...s, subject_json: "{}" })).rejects.toBeInstanceOf(ConsentRowConflict);
      expect((await journal.get(m.id!, A))!.agent_code).toBe(A);
    });
  });
}

suite("журнал согласий — память", async () => ({ store: new MemoryConsentStore() }));

describe("реквизиты до записи — отказ FIELD_INVALID, запись не пишется (журнал неизменяем)", () => {
  const j = new ConsentJournal(new MemoryConsentStore(), { now: () => T0 });
  const C = { merchant_id: "MER-1042", items: [{ sku: "a", qty: 1, price: 100 }], total: 100 };
  it.each([
    ["principal_ref — телефон", { principal_ref: "79990000000" }, "principal_ref"],
    ["principal_ref — 16 цифр в составе", { principal_ref: `prn_${DIGITS16}` }, "principal_ref"],
    ["principal_ref — адрес почты", { principal_ref: "ivan@example.ru" }, "principal_ref"],
    ["principal_ref — ФИО с пробелом", { principal_ref: "Иванов Иван" }, "principal_ref"],
    ["amount_limit 0", { amount_limit: 0 }, "amount_limit"],
    ["amount_limit дробное", { amount_limit: 1.5 }, "amount_limit"],
    ["currency строчными", { currency: "rub" }, "currency"],
    ["valid_to не RFC 3339", { valid_to: "Oct 24 2026" }, "valid_to"],
    ["valid_to без пояса", { valid_to: "2026-10-24T10:00:00" }, "valid_to"],
    ["INTENT с parent_id", { parent_id: "mnd_x" }, "parent_id"],
    ["INTENT с корзиной", { cart: C }, "cart"],
    ["CART без корзины", { type: "CART" as const }, "cart"],
    ["CART: итог больше суммы", { type: "CART" as const, amount_limit: 99, cart: C }, "cart.total"],
    ["CART: позиция без цены", { type: "CART" as const, cart: { ...C, items: [{ sku: "a", qty: 1 }] } }, "cart.items"],
    ["conditional без CONDITIONAL", { conditional: { provider: "cx:nsvr", deal_ref: "d" } }, "conditional"],
    ["CONDITIONAL без conditional", { settlement_mode: "CONDITIONAL" as const }, "conditional"],
    ["mode вне перечня", { mode: "AUTO" as never }, "mode"],
  ])("%s", async (_n, over, field) => {
    await expect(j.request(A, intent(over as Partial<MandateRequest>))).rejects.toEqual(rejected("FIELD_INVALID", field));
  });

  it("isOpaquePrincipalRef: непрозрачные идентификаторы проходят", () => {
    for (const v of ["prn_7f3c9a", "c-123456", "u_0a1b2c3d4e5f"]) expect(isOpaquePrincipalRef(v)).toBe(true);
  });
});

describe.skipIf(!DATABASE_URL)("журнал согласий — PostgreSQL", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("consent");
  });
  afterAll(async () => {
    await db?.close();
  });

  suite("общие проверки", async () => ({ store: new PgConsentStore(db.pool) }));

  it.each(["consent_mandates", "consent_subjects", "core_journal"])(
    "%s: UPDATE, DELETE, TRUNCATE отвергаются (инвариант 6)",
    async (table) => {
      const j = new ConsentJournal(new PgConsentStore(db.pool), { now: () => T0 });
      await j.request(A, intent());
      const col = table === "consent_subjects" ? "salt" : table === "core_journal" ? "kind" : "agent_code";
      await expect(db.pool.query(`UPDATE ${table} SET ${col} = ${col}`)).rejects.toThrow(/только добавление/);
      await expect(db.pool.query(`DELETE FROM ${table}`)).rejects.toThrow(/только добавление/);
      await expect(db.pool.query(`TRUNCATE ${table} CASCADE`)).rejects.toThrow(/только добавление/);
    },
  );

  it("id не по форме mnd_<UUIDv4> — отказ базы", async () => {
    await expect(
      db.pool.query("INSERT INTO consent_mandates (id, chain, agent_code, created_at) VALUES ('x', 'consent:mnd_x', $1, $2)", [
        A,
        T0.toISOString(),
      ]),
    ).rejects.toThrow(/check/i);
  });

  it("подменённый предмет (вставка в обход журнала) — ConsentIntegrityError", async () => {
    const store = new PgConsentStore(db.pool);
    const j = new ConsentJournal(store, { now: () => T0 });
    const id = "mnd_22222222-2222-4222-8222-222222222222";
    const chain = consentChain(id);
    await store.insertMandate({ id, chain, agent_code: A, created_at: T0.toISOString() });
    await store.insertSubject({ mandate_id: id, salt: "A".repeat(43), subject_json: canonicalJson({ subject: "иное", cart: null }) });
    const payload: MandateRequestedPayload = {
      type: "INTENT",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-10-24T10:00:00Z",
      merchant_scope: [],
      principal_ref: "prn_x",
      mode: "IMMEDIATE",
      parent_id: null,
      agent_code: A,
      subject_commitment: subjectCommitment("A".repeat(43), { subject: "молоко", cart: null }),
    };
    await new AsyncHashChainJournal(store.journal(chain), () => T0.toISOString()).append("MANDATE_REQUESTED", id, payload);
    await expect(j.get(id, A)).rejects.toBeInstanceOf(ConsentIntegrityError);
  });

  it("одновременные CART к одному родителю: цепочка не раздваивается, у каждого записанного свой seq", async () => {
    const store = new PgConsentStore(db.pool);
    const j = new ConsentJournal(store, { now: () => T0 });
    const p = await j.request(A, intent());
    await sign(store, p.id!);
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => j.request(A, cart(p.id!))));
    const ok = results.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []));
    for (const r of results) if (r.status === "rejected") expect(r.reason).toBeInstanceOf(JournalAppendConflict);
    expect(ok.length).toBeGreaterThan(0);
    const chain = new AsyncHashChainJournal(store.journal(consentChain(p.id!)));
    expect(await chain.verify()).toEqual({ ok: true });
    const rows = await store.journal(consentChain(p.id!)).all();
    expect(rows.length).toBe(2 + ok.length);
    expect(new Set(rows.map((r) => r.seq)).size).toBe(rows.length);
    for (const c of ok) expect((await j.get(c.id!, A))!.status).toBe("PENDING_SIGNATURE");
  });
});

describe("подмена записи журнала и предмета — ConsentIntegrityError (память)", () => {
  it("изменённый payload в хранилище — цепочка не проходит verify", async () => {
    const store = new MemoryConsentStore();
    const j = new ConsentJournal(store, { now: () => T0 });
    const m = await j.request(A, intent());
    const rows = (await store.journal(consentChain(m.id!)).all()) as JournalEntry[];
    // Подставная поломка: замороженная запись подменяется целиком в массиве хранилища.
    rows[0] = { ...rows[0]!, payload: { ...(rows[0]!.payload as object), amount_limit: 99_999_999 } };
    await expect(j.get(m.id!, A)).rejects.toBeInstanceOf(ConsentIntegrityError);
  });

  it("предмет не читается как JSON — ConsentIntegrityError, а не SyntaxError", async () => {
    const store = new MemoryConsentStore();
    const j = new ConsentJournal(store, { now: () => T0 });
    const id = "mnd_55555555-5555-4555-8555-555555555555";
    await store.insertMandate({ id, chain: consentChain(id), agent_code: A, created_at: T0.toISOString() });
    await store.insertSubject({ mandate_id: id, salt: "A".repeat(43), subject_json: "{не json" });
    await new AsyncHashChainJournal(store.journal(consentChain(id)), () => T0.toISOString()).append("MANDATE_REQUESTED", id, {
      agent_code: A,
      valid_to: "2026-10-24T10:00:00Z",
      subject_commitment: "0".repeat(64),
    });
    await expect(j.get(id, A)).rejects.toBeInstanceOf(ConsentIntegrityError);
  });
});

describe("deriveStatus — свёртка записей (A7 п. 4; инвариант 3)", () => {
  const id = "mnd_33333333-3333-4333-8333-333333333333";
  const at = T0.toISOString();
  const e = (kind: string, ref = `${id}:${kind}`, parent_ref: string | null = id): JournalEntry => ({
    seq: 0,
    at,
    kind,
    ref,
    parent_ref,
    payload: { valid_to: "2026-10-24T10:00:00Z" },
    prev_hash: "",
    hash: "",
  });
  const head = e("MANDATE_REQUESTED", id, null);

  it.each([
    [[], "PENDING_SIGNATURE"],
    [["MANDATE_SIGNED"], "ACTIVE"],
    [["MANDATE_REJECTED"], "REJECTED"],
    [["MANDATE_REVOKED"], "REVOKED"],
    [["MANDATE_SIGNED", "MANDATE_REVOKED"], "REVOKED"],
    [["MANDATE_SIGNED", "MANDATE_RELINQUISHED"], "REVOKED"],
  ])("%j → %s", (kinds, status) => {
    expect(deriveStatus(id, [head, ...kinds.map((k) => e(k))], T0)).toBe(status);
  });

  it("дочерний CART (MANDATE_REQUESTED с parent_ref) на статус родителя не влияет", () => {
    const child = e("MANDATE_REQUESTED", "mnd_child", id);
    expect(deriveStatus(id, [head, child, e("MANDATE_SIGNED")], T0)).toBe("ACTIVE");
  });

  it("REVOKED и REJECTED после valid_to не становятся EXPIRED; ACTIVE — становится", () => {
    const late = new Date("2026-10-25T00:00:00Z");
    expect(deriveStatus(id, [head, e("MANDATE_REVOKED")], late)).toBe("REVOKED");
    expect(deriveStatus(id, [head, e("MANDATE_REJECTED")], late)).toBe("REJECTED");
    expect(deriveStatus(id, [head, e("MANDATE_SIGNED")], late)).toBe("EXPIRED");
  });

  it.each([
    ["неизвестный вид записи", [head, e("MANDATE_EXTENDED")]],
    ["повтор головной записи", [head, e("MANDATE_REQUESTED", id, null)]],
    ["вторая подпись", [head, e("MANDATE_SIGNED"), e("MANDATE_SIGNED")]],
    ["подпись после отзыва", [head, e("MANDATE_REVOKED"), e("MANDATE_SIGNED")]],
    ["подпись после отказа", [head, e("MANDATE_REJECTED"), e("MANDATE_SIGNED")]],
    ["нет записи мандата первой", [e("MANDATE_SIGNED")]],
    ["valid_to не читается", [{ ...head, payload: { valid_to: "не дата" } }]],
    ["valid_to не RFC 3339", [{ ...head, payload: { valid_to: "Oct 24 2026" } }]],
  ])("%s — ConsentStateUnknown", (_name, entries) => {
    expect(() => deriveStatus(id, entries, T0)).toThrow(ConsentStateUnknown);
  });
});

describe("номера миграций: ядро < 100, Платформа ≥ 100", () => {
  it("каталоги ядра и Платформы — в своих номерах", () => {
    expect(() => assertMigrationRanges(migrationsDir(), platformMigrationsDir())).not.toThrow();
  });
  it("файл Платформы с номером ядра — отказ", () => {
    const d = mkdtempSync(join(tmpdir(), "mig-"));
    writeFileSync(join(d, "005_x.sql"), "");
    expect(() => assertMigrationRanges(migrationsDir(), d)).toThrow(/005_x\.sql/);
  });
});
