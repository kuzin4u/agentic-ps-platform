// П2 Журнал согласий (PS-06 К1.2): запись мандата, статус — свёртка записей, обязательство предмета, только вставка.
// Одни и те же проверки — на памяти ядра (всегда) и на PostgreSQL (в CI, РП30 п. 7).
// Длинные цифровые строки — не номера карт: проверку Луна не проходят (инвариант 1, guard.py).
import { createHash, randomUUID } from "node:crypto";
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
  ConsentKeyReused,
  ConsentStateUnknown,
  consentChain,
  deriveStatus,
  MANDATE_ID,
  mandateIdFor,
  subjectCommitment,
  withParentStatus,
  type MandateRequestedPayload,
} from "../../src/consent/model.js";
import { ConsentRowConflict, MemoryConsentStore, PgConsentStore, type ConsentStore } from "../../src/consent/store.js";
import { ConsentRequestRejected, isOpaquePrincipalRef } from "../../src/consent/terms.js";
import { signDirect } from "../support/consent-sign.js";
import { assertMigrationRanges, platformMigrationsDir } from "../../src/shared/migrations.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const A = "nspk:agent:consent-a:v1";
const B = "nspk:agent:consent-b:v1";
const T0 = new Date("2026-10-17T10:00:00Z");
/** Хэш нового Idempotency-Key: у каждого запроса свой ключ — свой мандат (РП33 доп.). */
const key = (): string => createHash("sha256").update(randomUUID()).digest("hex");
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

/** Подпись принципала в обход ПИ-8: MANDATE_SIGNED и строка SIGN порядка пары (РП46 (а)). */
const sign = (store: ConsentStore, id: string): Promise<void> => signDirect(store, id, T0);

const rejected = (reason: string, field: string) =>
  expect.objectContaining({ reason, field }) as unknown as ConsentRequestRejected;

function suite(name: string, open: () => Promise<{ store: ConsentStore }>) {
  describe(name, () => {
    let store: ConsentStore;
    let now = T0;
    let journal: ConsentJournal;
    beforeAll(async () => {
      ({ store } = await open());
      journal = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => now });
    });

    const signedIntent = async (over: Partial<MandateRequest> = {}) => {
      const p = await journal.request(A, key(), intent(over));
      await sign(store, p.id!);
      return p;
    };

    it("запрос INTENT: PENDING_SIGNATURE, id Платформы, agent_code — из обращения, хэш записи в ответе", async () => {
      now = T0;
      const m = await journal.request(A, key(), { ...intent(), ...({ agent_code: B } as object) });
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
        revocation_order: "agent:own",
      } as MandateRequest;
      (body.conditional as Record<string, unknown>).phone = "+79990000000";
      const m = await journal.request(A, key(), body);
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
          "revocation_order",
          "settlement_mode",
          "subject_commitment",
          "type",
          "valid_to",
        ].sort(),
      );
      expect(p.conditional).toEqual({ provider: "cx:nsvr", deal_ref: "deal-1" });
      // Порядок отзыва — от Платформы, не из тела агента (РП37).
      expect(p.revocation_order).toBe("bank:test:revocation:v1");
      const json = canonicalJson(p) + canonicalJson(await journal.get(m.id!, A));
      for (const leak of ["qualified", DIGITS16, "+79990000000", "mnd_forged"]) expect(json).not.toContain(leak);
      expect(m.status).toBe("PENDING_SIGNATURE");
      expect(m).not.toHaveProperty("signature_type");
    });

    it("предмет не раскрыт в журнале: в записи только subject_commitment, соль у одинаковых предметов разная", async () => {
      const m1 = await journal.request(A, key(), intent());
      const m2 = await journal.request(A, key(), intent());
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
      const m = await journal.request(A, key(), intent());
      expect(await journal.get(m.id!, B)).toBeUndefined();
      expect(await journal.get("mnd_00000000-0000-4000-8000-000000000000", A)).toBeUndefined();
    });

    it("CART под действующим INTENT — в цепочке родителя, статус родителя не меняется", async () => {
      const p = await signedIntent();
      const c = await journal.request(A, key(), cart(p.id!));
      expect((await store.getMandate(c.id!))!.chain).toBe(consentChain(p.id!));
      expect(c.cart?.total).toBe(12_900);
      expect(c.status).toBe("PENDING_SIGNATURE");
      expect((await journal.get(p.id!, A))!.status).toBe("ACTIVE");
      expect((await journal.get(c.id!, A))!.parent_id).toBe(p.id);
    });

    it("CART: родитель чужой, без записи журнала, не подписан, сам CART — отказ, запись не пишется", async () => {
      const p = await signedIntent();
      await expect(journal.request(B, key(), cart(p.id!))).rejects.toEqual(rejected("PARENT_NOT_FOUND", "parent_id"));
      const orphan = "mnd_44444444-4444-4444-8444-444444444444";
      await store.insertMandate({ id: orphan, chain: consentChain(orphan), agent_code: A, created_at: T0.toISOString(), terms_hash: "0".repeat(64) });
      await sign(store, orphan);
      await expect(journal.request(A, key(), cart(orphan))).rejects.toEqual(rejected("PARENT_NOT_FOUND", "parent_id"));
      const pending = await journal.request(A, key(), intent());
      await expect(journal.request(A, key(), cart(pending.id!))).rejects.toEqual(rejected("PARENT_NOT_ACTIVE", "parent_id"));
      const c = await journal.request(A, key(), cart(p.id!));
      await sign(store, c.id!);
      await expect(journal.request(A, key(), cart(c.id!))).rejects.toEqual(rejected("PARENT_MISMATCH", "parent_id"));
      const before = (await store.journal(consentChain(p.id!)).all()).length;
      await expect(journal.request(A, key(), cart(p.id!, { amount_limit: 60_000 }))).rejects.toBeInstanceOf(ConsentRequestRejected);
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
      await expect(journal.request(A, key(), cart(p.id!, over as Partial<MandateRequest>))).rejects.toEqual(rejected(reason, field));
    });

    it("наступил valid_to — EXPIRED без новой записи; valid_to в прошлом при запросе — отказ", async () => {
      now = T0;
      const m = await journal.request(A, key(), intent());
      now = new Date("2026-10-24T10:00:00Z");
      expect((await journal.get(m.id!, A))!.status).toBe("EXPIRED");
      await expect(journal.request(A, key(), intent())).rejects.toEqual(rejected("FIELD_INVALID", "valid_to"));
      now = T0;
    });

    it("индекс без записи журнала (запись не завершилась) — мандата нет", async () => {
      const id = "mnd_11111111-1111-4111-8111-111111111111";
      await store.insertMandate({ id, chain: consentChain(id), agent_code: A, created_at: T0.toISOString(), terms_hash: "0".repeat(64) });
      expect(await journal.get(id, A)).toBeUndefined();
    });

    it("повторная вставка в индекс и предмет — ConsentRowConflict, не перезапись", async () => {
      const m = await journal.request(A, key(), intent());
      const row = (await store.getMandate(m.id!))!;
      await expect(store.insertMandate({ ...row, agent_code: B })).rejects.toBeInstanceOf(ConsentRowConflict);
      const s = (await store.getSubject(m.id!))!;
      await expect(store.insertSubject({ ...s, subject_json: "{}" })).rejects.toBeInstanceOf(ConsentRowConflict);
      expect((await journal.get(m.id!, A))!.agent_code).toBe(A);
    });

    // РП33 доп.: id от (агент, ключ); повтор — тот же мандат или 409, прерванная запись доделывается после сверки.
    const heads = async (id: string) => {
      const row = (await store.getMandate(id))!;
      return (await store.journal(row.chain).all()).filter((e) => e.ref === id && e.kind === "MANDATE_REQUESTED");
    };
    /** Хранилище, у которого первый вызов метода падает: сбой между записями. */
    const failingOnce = (method: "insertSubject" | "journal"): ConsentStore => {
      let failed = false;
      const once = () => {
        if (failed) return false;
        failed = true;
        return true;
      };
      return {
        insertMandate: (r) => store.insertMandate(r),
        journalWithEvent: (c, d, sg) => store.journalWithEvent(c, d, sg),
        pairPosition: (p, id) => store.pairPosition(p, id),
        insertRevokeAll: (p, ref, r, at) => store.insertRevokeAll(p, ref, r, at),
        pairSigns: (p, before) => store.pairSigns(p, before),
        listEvents: (a, after, n) => store.listEvents(a, after, n),
        claimDue: (t, l, n) => store.claimDue(t, l, n),
        finish: (id, a, o) => store.finish(id, a, o),
        delivery: (id) => store.delivery(id),
        getMandate: (id) => store.getMandate(id),
        getSubject: (id) => store.getSubject(id),
        insertSubject: async (r) => {
          if (method === "insertSubject" && once()) throw new Error("сбой после индекса");
          return store.insertSubject(r);
        },
        journal: (chain) => {
          const inner = store.journal(chain);
          return {
            ...(inner.genesis !== undefined ? { genesis: inner.genesis } : {}),
            last: () => inner.last(),
            all: () => inner.all(),
            append: async (e) => {
              if (method === "journal" && once()) throw new Error("сбой после предмета");
              return inner.append(e);
            },
          };
        },
      };
    };

    it("повтор с тем же ключом и тем же запросом — тот же мандат, одна запись; другой агент — другой id", async () => {
      now = T0;
      const k = key();
      const m1 = await journal.request(A, k, intent());
      const m2 = await journal.request(A, k, intent());
      expect(m2).toEqual(m1);
      expect(m1.id).toBe(mandateIdFor(A, k));
      expect(await heads(m1.id!)).toHaveLength(1);
      const other = await journal.request(B, k, intent());
      expect(other.id).not.toBe(m1.id);
    });

    it("тот же ключ, другой запрос — ConsentKeyReused, вторая запись не пишется (в любой срок)", async () => {
      now = T0;
      const k = key();
      const m = await journal.request(A, k, intent());
      for (const over of [{ amount_limit: 1 }, { subject: "хлеб" }, { merchant_scope: ["MER-1042"] }]) {
        await expect(journal.request(A, k, intent(over))).rejects.toBeInstanceOf(ConsentKeyReused);
      }
      expect(await heads(m.id!)).toHaveLength(1);
    });

    it("тот же ключ и запрос после valid_to — тот же мандат со статусом EXPIRED, не отказ по сроку", async () => {
      now = T0;
      const k = key();
      const m = await journal.request(A, k, intent());
      now = new Date("2026-11-01T00:00:00Z");
      const again = await journal.request(A, k, intent());
      expect([again.id, again.status]).toEqual([m.id, "EXPIRED"]);
      expect(await heads(m.id!)).toHaveLength(1);
      now = T0;
    });

    it.each(["insertSubject", "journal"] as const)("сбой %s — повтор доделывает запись, одна запись", async (method) => {
      now = T0;
      const k = key();
      const broken = new ConsentJournal(failingOnce(method), { revocationOrder: () => "bank:test:revocation:v1", now: () => now });
      await expect(broken.request(A, k, intent())).rejects.toThrow(/сбой/);
      const id = mandateIdFor(A, k);
      expect(await journal.get(id, A)).toBeUndefined();
      const m = await broken.request(A, k, intent());
      expect(m.id).toBe(id);
      expect(await heads(id)).toHaveLength(1);
      expect((await journal.get(id, A))!.subject).toBe("молоко 2 л");
    });

    it("прерванная запись и другой запрос — ConsentKeyReused, чужой запрос не доделывается", async () => {
      now = T0;
      for (const method of ["insertSubject", "journal"] as const) {
        const k = key();
        const broken = new ConsentJournal(failingOnce(method), { revocationOrder: () => "bank:test:revocation:v1", now: () => now });
        await expect(broken.request(A, k, intent())).rejects.toThrow(/сбой/);
        // После индекса предмета нет — расходится цепочка (другой родитель); после предмета — и сам предмет.
        const other = method === "journal" ? intent({ subject: "хлеб" }) : cart(mandateIdFor(A, key()));
        await expect(journal.request(A, k, other)).rejects.toBeInstanceOf(ConsentKeyReused);
        expect(await journal.get(mandateIdFor(A, k), A)).toBeUndefined();
      }
    });

    it("прерванная запись: другие реквизиты с тем же предметом, CART вместо INTENT, неверный запрос — ConsentKeyReused", async () => {
      now = T0;
      const parent = await signedIntent();
      for (const method of ["insertSubject", "journal"] as const) {
        const k = key();
        const broken = new ConsentJournal(failingOnce(method), { revocationOrder: () => "bank:test:revocation:v1", now: () => now });
        await expect(broken.request(A, k, intent())).rejects.toThrow(/сбой/);
        for (const other of [intent({ amount_limit: 100_000 }), cart(parent.id!), intent({ currency: "rub" })]) {
          await expect(journal.request(A, k, other)).rejects.toBeInstanceOf(ConsentKeyReused);
        }
        expect(await journal.get(mandateIdFor(A, k), A)).toBeUndefined();
      }
    });

    it("записанный мандат и неверный запрос тем же ключом — ConsentKeyReused, не отказ по реквизитам", async () => {
      now = T0;
      const k = key();
      await journal.request(A, k, intent());
      await expect(journal.request(A, k, intent({ principal_ref: "79990000000" }))).rejects.toBeInstanceOf(ConsentKeyReused);
    });

    it("индекс вставлен другим обработчиком между чтением и вставкой (ConsentRowConflict) — ветка повтора, тот же мандат", async () => {
      now = T0;
      const k = key();
      const m = await journal.request(A, k, intent());
      let hidden = true;
      const racing: ConsentStore = {
        insertMandate: (r) => store.insertMandate(r),
        journalWithEvent: (c, d, sg) => store.journalWithEvent(c, d, sg),
        pairPosition: (p, id) => store.pairPosition(p, id),
        insertRevokeAll: (p, ref, r, at) => store.insertRevokeAll(p, ref, r, at),
        pairSigns: (p, before) => store.pairSigns(p, before),
        listEvents: (a, after, n) => store.listEvents(a, after, n),
        claimDue: (t, l, n) => store.claimDue(t, l, n),
        finish: (id, a, o) => store.finish(id, a, o),
        delivery: (id) => store.delivery(id),
        getMandate: async (id) => {
          if (id === m.id && hidden) {
            hidden = false;
            return undefined;
          }
          return store.getMandate(id);
        },
        getSubject: (id) => store.getSubject(id),
        insertSubject: (r) => store.insertSubject(r),
        journal: (chain) => store.journal(chain),
      };
      const again = await new ConsentJournal(racing, { revocationOrder: () => "bank:test:revocation:v1", now: () => now }).request(A, k, intent());
      expect(again.id).toBe(m.id);
      expect(await heads(m.id!)).toHaveLength(1);
    });

    it("предел перед вставкой в журнал — индекс и предмет без записи; повтор доделывает с сохранённой солью", async () => {
      now = T0;
      const k = key();
      let calls = 0;
      const deadline = () => {
        if (++calls === 3) throw new Error("предел времени");
      };
      await expect(journal.request(A, k, intent(), deadline)).rejects.toThrow(/предел/);
      const id = mandateIdFor(A, k);
      const salt = (await store.getSubject(id))!.salt;
      expect(await journal.get(id, A)).toBeUndefined();
      const m = await journal.request(A, k, intent());
      expect(m.id).toBe(id);
      expect((await store.getSubject(id))!.salt).toBe(salt);
      expect(await heads(id)).toHaveLength(1);
    });

    it("CART записан, родитель затем отозван — повтор возвращает тот же CART; CART прерван, родитель отозван — отказ, записи нет", async () => {
      now = T0;
      const p = await signedIntent();
      const k = key();
      const c = await journal.request(A, k, cart(p.id!));
      const k2 = key();
      const broken = new ConsentJournal(failingOnce("journal"), { revocationOrder: () => "bank:test:revocation:v1", now: () => now });
      await expect(broken.request(A, k2, cart(p.id!))).rejects.toThrow(/сбой/);
      const row = (await store.getMandate(p.id!))!;
      await new AsyncHashChainJournal(store.journal(row.chain), () => T0.toISOString()).append("MANDATE_REVOKED", `${p.id}:revoked`, {}, p.id);
      const again = await journal.request(A, k, cart(p.id!));
      expect([again.id, again.status]).toEqual([c.id, "REVOKED"]);
      await expect(journal.request(A, k2, cart(p.id!))).rejects.toEqual(rejected("PARENT_NOT_ACTIVE", "parent_id"));
      expect(await journal.get(mandateIdFor(A, k2), A)).toBeUndefined();
    });

    // РП35: статус CART — вместе с родителем; записей потомкам нет.
    const appendTo = async (id: string, kind: string) => {
      const row = (await store.getMandate(id))!;
      await new AsyncHashChainJournal(store.journal(row.chain), () => now.toISOString()).append(kind, `${id}:${kind}`, {}, id);
    };

    it.each(["MANDATE_REVOKED", "MANDATE_RELINQUISHED"])("родитель %s — все его CART REVOKED, собственный REJECTED сохраняется", async (kind) => {
      now = T0;
      const p = await signedIntent();
      const pending = await journal.request(A, key(), cart(p.id!));
      const active = await journal.request(A, key(), cart(p.id!));
      await sign(store, active.id!);
      const rejectedC = await journal.request(A, key(), cart(p.id!));
      await appendTo(rejectedC.id!, "MANDATE_REJECTED");
      const before = (await store.journal(consentChain(p.id!)).all()).length;
      await appendTo(p.id!, kind);
      expect((await journal.get(pending.id!, A))!.status).toBe("REVOKED");
      expect((await journal.get(active.id!, A))!.status).toBe("REVOKED");
      expect((await journal.get(rejectedC.id!, A))!.status).toBe("REJECTED");
      // Одна новая запись — у родителя; потомкам записей не пишется.
      expect((await store.journal(consentChain(p.id!)).all()).length).toBe(before + 1);
    });

    it("собственный отзыв CART не меняет статус родителя и соседних CART", async () => {
      now = T0;
      const p = await signedIntent();
      const c1 = await journal.request(A, key(), cart(p.id!));
      const c2 = await journal.request(A, key(), cart(p.id!));
      await sign(store, c2.id!);
      await appendTo(c1.id!, "MANDATE_REVOKED");
      expect((await journal.get(c1.id!, A))!.status).toBe("REVOKED");
      expect((await journal.get(c2.id!, A))!.status).toBe("ACTIVE");
      expect((await journal.get(p.id!, A))!.status).toBe("ACTIVE");
    });

    it("гонка: отзыв родителя записан между проверкой и записью CART — CART после отзыва, статус REVOKED с первого ответа", async () => {
      now = T0;
      const p = await signedIntent();
      const k = key();
      const cartId = mandateIdFor(A, k);
      let injected = false;
      const racing: ConsentStore = {
        insertMandate: (r) => store.insertMandate(r),
        journalWithEvent: (c, d, sg) => store.journalWithEvent(c, d, sg),
        pairPosition: (p, id) => store.pairPosition(p, id),
        insertRevokeAll: (p, ref, r, at) => store.insertRevokeAll(p, ref, r, at),
        pairSigns: (p, before) => store.pairSigns(p, before),
        listEvents: (a, after, n) => store.listEvents(a, after, n),
        claimDue: (t, l, n) => store.claimDue(t, l, n),
        finish: (id, a, o) => store.finish(id, a, o),
        delivery: (id) => store.delivery(id),
        getMandate: (id) => store.getMandate(id),
        getSubject: (id) => store.getSubject(id),
        insertSubject: (r) => store.insertSubject(r),
        journal: (chain) => {
          const inner = store.journal(chain);
          return {
            ...(inner.genesis !== undefined ? { genesis: inner.genesis } : {}),
            last: () => inner.last(),
            all: () => inner.all(),
            append: async (e) => {
              if (e.ref === cartId && !injected) {
                injected = true;
                await appendTo(p.id!, "MANDATE_REVOKED");
              }
              return inner.append(e);
            },
          };
        },
      };
      const c = await new ConsentJournal(racing, { revocationOrder: () => "bank:test:revocation:v1", now: () => now }).request(A, k, cart(p.id!));
      expect(injected).toBe(true);
      expect(c.status).toBe("REVOKED");
      const rows = await store.journal(consentChain(p.id!)).all();
      const revokedAt = rows.findIndex((e) => e.kind === "MANDATE_REVOKED" && e.parent_ref === p.id);
      const cartAt = rows.findIndex((e) => e.ref === cartId);
      expect(cartAt).toBeGreaterThan(revokedAt);
      expect(await new AsyncHashChainJournal(store.journal(consentChain(p.id!))).verify()).toEqual({ ok: true });
      expect((await journal.get(cartId, A))!.status).toBe("REVOKED");
      // Повтор тем же ключом — тот же ответ (РП33 доп. п. 6).
      expect((await journal.request(A, k, cart(p.id!))).status).toBe("REVOKED");
    });

    it("beforeWrite отказал перед предметом — записан только индекс; повтор доделывает", async () => {
      now = T0;
      const k = key();
      let calls = 0;
      const deadline = () => {
        if (++calls === 2) throw new Error("предел времени");
      };
      await expect(journal.request(A, k, intent(), deadline)).rejects.toThrow(/предел/);
      const id = mandateIdFor(A, k);
      expect(await store.getMandate(id)).toBeDefined();
      expect(await store.getSubject(id)).toBeUndefined();
      const m = await journal.request(A, k, intent());
      expect(m.id).toBe(id);
      expect(await heads(id)).toHaveLength(1);
    });
  });
}

suite("журнал согласий — память", async () => ({ store: new MemoryConsentStore() }));

describe("id мандата — UUID v8 от (агент, хэш Idempotency-Key) (РП33 доп.)", () => {
  const KH = createHash("sha256").update("key-1", "utf8").digest("hex");
  it("вектор: агент + ключ → id; маска — v8, прежние v4 действительны", () => {
    // Вычислено отдельно от кода (node -e, SHA-256 и биты версии и варианта вручную).
    expect(KH).toBe("be2974546978e3739e6d6da85c4be9f334ce32df2b9fd4b6ff1b55c0d57e9d44");
    expect(mandateIdFor(A, KH)).toBe("mnd_add79a9f-a832-88e7-8dc3-addca4295d26");
    expect(mandateIdFor(A, KH)).toMatch(MANDATE_ID);
    expect(MANDATE_ID.test("mnd_11111111-1111-4111-8111-111111111111")).toBe(true);
    for (const v of ["1", "5", "7", "9"]) expect(MANDATE_ID.test(`mnd_11111111-1111-${v}111-8111-111111111111`)).toBe(false);
  });
  it("разные агенты, ключи — разные id; хэш ключа не в hex или agent_code с переводом строки — отказ", () => {
    expect(mandateIdFor(B, KH)).not.toBe(mandateIdFor(A, KH));
    expect(mandateIdFor(A, key())).not.toBe(mandateIdFor(A, KH));
    expect(() => mandateIdFor(A, "key-1")).toThrow();
    expect(() => mandateIdFor(`${A}\nx`, KH)).toThrow();
  });
});

describe("реквизиты до записи — отказ FIELD_INVALID, запись не пишется (журнал неизменяем)", () => {
  const j = new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
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
    await expect(j.request(A, key(), intent(over as Partial<MandateRequest>))).rejects.toEqual(rejected("FIELD_INVALID", field));
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
      const j = new ConsentJournal(new PgConsentStore(db.pool), { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
      await j.request(A, key(), intent());
      const col = table === "consent_subjects" ? "salt" : table === "core_journal" ? "kind" : "agent_code";
      await expect(db.pool.query(`UPDATE ${table} SET ${col} = ${col}`)).rejects.toThrow(/только добавление/);
      await expect(db.pool.query(`DELETE FROM ${table}`)).rejects.toThrow(/только добавление/);
      await expect(db.pool.query(`TRUNCATE ${table} CASCADE`)).rejects.toThrow(/только добавление/);
    },
  );

  it("id не по форме mnd_<UUID v4 или v8> — отказ базы", async () => {
    await expect(
      db.pool.query(
        "INSERT INTO consent_mandates (id, chain, agent_code, created_at, terms_hash) VALUES ('x', 'consent:mnd_x', $1, $2, $3)",
        [A, T0.toISOString(), "0".repeat(64)],
      ),
    ).rejects.toThrow(/check/i);
  });

  it("подменённый предмет (вставка в обход журнала) — ConsentIntegrityError", async () => {
    const store = new PgConsentStore(db.pool);
    const j = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
    const id = "mnd_22222222-2222-4222-8222-222222222222";
    const chain = consentChain(id);
    await store.insertMandate({ id, chain, agent_code: A, created_at: T0.toISOString(), terms_hash: "0".repeat(64) });
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
      revocation_order: "bank:test:revocation:v1",
      subject_commitment: subjectCommitment("A".repeat(43), { subject: "молоко", cart: null }),
    };
    await new AsyncHashChainJournal(store.journal(chain), () => T0.toISOString()).append("MANDATE_REQUESTED", id, payload);
    await expect(j.get(id, A)).rejects.toBeInstanceOf(ConsentIntegrityError);
  });

  it("одновременные CART к одному родителю: цепочка не раздваивается, у каждого записанного свой seq", async () => {
    const store = new PgConsentStore(db.pool);
    const j = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
    const p = await j.request(A, key(), intent());
    await sign(store, p.id!);
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => j.request(A, key(), cart(p.id!))));
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
    const j = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
    const m = await j.request(A, key(), intent());
    const rows = (await store.journal(consentChain(m.id!)).all()) as JournalEntry[];
    // Подставная поломка: замороженная запись подменяется целиком в массиве хранилища.
    rows[0] = { ...rows[0]!, payload: { ...(rows[0]!.payload as object), amount_limit: 99_999_999 } };
    await expect(j.get(m.id!, A)).rejects.toBeInstanceOf(ConsentIntegrityError);
  });

  it("предмет не читается как JSON — ConsentIntegrityError, а не SyntaxError", async () => {
    const store = new MemoryConsentStore();
    const j = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1", now: () => T0 });
    const id = "mnd_55555555-5555-4555-8555-555555555555";
    await store.insertMandate({ id, chain: consentChain(id), agent_code: A, created_at: T0.toISOString(), terms_hash: "0".repeat(64) });
    await store.insertSubject({ mandate_id: id, salt: "A".repeat(43), subject_json: "{не json" });
    await new AsyncHashChainJournal(store.journal(consentChain(id)), () => T0.toISOString()).append("MANDATE_REQUESTED", id, {
      agent_code: A,
      valid_to: "2026-10-24T10:00:00Z",
      subject_commitment: "0".repeat(64),
    });
    await expect(j.get(id, A)).rejects.toBeInstanceOf(ConsentIntegrityError);
  });
});

describe("withParentStatus — статус CART вместе с родителем (РП35)", () => {
  const S = ["PENDING_SIGNATURE", "ACTIVE", "REJECTED", "EXPIRED", "REVOKED"] as const;
  it("собственные REVOKED и REJECTED сохраняются; родитель REVOKED/REJECTED — REVOKED; EXPIRED — EXPIRED; иначе свой", () => {
    for (const own of S) {
      for (const parent of S) {
        const expected =
          own === "REVOKED" || own === "REJECTED"
            ? own
            : parent === "REVOKED" || parent === "REJECTED"
              ? "REVOKED"
              : parent === "EXPIRED"
                ? "EXPIRED"
                : own;
        expect(withParentStatus(own, parent), `${own} / ${parent}`).toBe(expected);
      }
    }
    expect(withParentStatus("ACTIVE", "EXPIRED")).toBe("EXPIRED");
    expect(withParentStatus("PENDING_SIGNATURE", "REJECTED")).toBe("REVOKED");
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

  it("точный дубль записанного решения (та же запись участника) пропускается — РП36 доп.", () => {
    expect(deriveStatus(id, [head, e("MANDATE_SIGNED"), e("MANDATE_SIGNED")], T0)).toBe("ACTIVE");
    expect(deriveStatus(id, [head, e("MANDATE_REJECTED"), e("MANDATE_REJECTED")], T0)).toBe("REJECTED");
    expect(deriveStatus(id, [head, e("MANDATE_SIGNED"), e("MANDATE_REVOKED"), e("MANDATE_SIGNED")], T0)).toBe("REVOKED");
  });

  it.each([
    ["второй отзыв", ["MANDATE_REVOKED", "MANDATE_REVOKED"], "REVOKED"],
    ["отзыв клиентом и отказ агента", ["MANDATE_SIGNED", "MANDATE_RELINQUISHED", "MANDATE_REVOKED"], "REVOKED"],
    ["подпись после отзыва", ["MANDATE_REVOKED", "MANDATE_SIGNED"], "REVOKED"],
    ["отказ клиента после отзыва", ["MANDATE_RELINQUISHED", "MANDATE_REJECTED"], "REVOKED"],
    ["отзыв после отказа клиента", ["MANDATE_REJECTED", "MANDATE_REVOKED"], "REJECTED"],
    ["отказ агента после отказа клиента", ["MANDATE_REJECTED", "MANDATE_RELINQUISHED"], "REJECTED"],
  ])("РП38 п. 5: %s — %s без ConsentStateUnknown", (_name, kinds, status) => {
    expect(deriveStatus(id, [head, ...kinds.map((k) => e(k))], T0)).toBe(status);
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
    ["вторая подпись с другой записью", [head, e("MANDATE_SIGNED"), { ...e("MANDATE_SIGNED"), payload: { signature: "другая" } }]],
    ["отказ после подписи", [head, e("MANDATE_SIGNED"), e("MANDATE_REJECTED")]],
    ["повтор головной записи после отзыва", [head, e("MANDATE_REVOKED"), e("MANDATE_REQUESTED", id, null)]],
    ["неизвестный вид записи после отзыва", [head, e("MANDATE_REVOKED"), e("MANDATE_EXTENDED")]],
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
