// П10 / П2 Отзыв всех полномочий клиента одним действием (PS-20 ч. 2 К1.3; РП45 п. 4, РП46 (а); A3 п. 6.1–6.3, ФП9):
// ПИ-8 POST /participants/v1/principals/{ref}/revoke-all с подписью банка — метка пары по порядку фиксации, затем
// MANDATE_REVOKED и mandate.revoked каждому ACTIVE-мандату пары, подписанному до метки (сначала CART, затем корни).
// Здесь — память; гонка «подпись ↔ метка» на двух экземплярах PostgreSQL — revoke-all-pg.test.ts.
import { canonicalJson, type AsyncJournalStore } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import { MemoryConsentStore, type ConsentStore } from "../../src/consent/store.js";
import type { JournalEntry } from "@kuzin4u/agentic-core";
import { signDirect } from "../support/consent-sign.js";
import { A, decide, intent, mk, setup, T0, type Ctx } from "../support/state.js";

const cart = (parent_id: string) => ({
  type: "CART" as const,
  parent_id,
  subject: "молоко 2 л",
  amount_limit: 12_900,
  currency: "RUB",
  valid_to: "2026-10-24T10:00:00Z",
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE" as const,
  cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }], total: 12_900 },
});

function record(c: Ctx, over: Partial<{ principal_ref: string; revocation_ref: string; revoked_at: string }> = {}) {
  const r = {
    participant_code: c.emu.participant_code,
    kid: c.emu.trustedKey.kid,
    principal_ref: "prn_7f3c9a",
    revocation_ref: "rva-0001",
    revoked_at: T0.toISOString(),
    ...over,
  };
  return { ...r, signature: c.emu.signPrincipalRevocation(r) };
}

async function revokeAll(c: Ctx, over: Parameters<typeof record>[1] = {}, tamper?: (b: Record<string, unknown>) => void) {
  const { principal_ref, ...body } = record(c, over);
  tamper?.(body);
  const res = await c.app.inject({ method: "POST", url: `/participants/v1/principals/${principal_ref}/revoke-all`, payload: body });
  return { status: res.statusCode, body: res.json() as Record<string, unknown> };
}

const status = async (c: Ctx, id: string) => (await c.consent.get(id, A))?.status;

/** Записи цепочки мандата id. */
async function chainOf(store: ConsentStore, id: string): Promise<readonly JournalEntry[]> {
  const row = (await store.getMandate(id))!;
  return store.journal(row.chain).all();
}

describe("revoke-all: метка пары, затем записи (РП45 п. 4, РП46 (а))", () => {
  it("ACTIVE INTENT и CART пары — REVOKED с записью и событием, CART раньше корня; PENDING_SIGNATURE не трогается; 200 после всех записей", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const p = await mk(c);
    expect(await decide(c, p)).toBe(200);
    const k = await mk(c, cart(p.id));
    expect(await decide(c, k)).toBe(200);
    const q = await mk(c, intent({ subject: "хлеб" }));
    expect(await decide(c, q)).toBe(200);
    const pending = await mk(c, intent({ subject: "сыр" }));

    const r = await revokeAll(c);
    expect(r).toEqual({ status: 200, body: { principal_ref: "prn_7f3c9a", revocation_ref: "rva-0001", revoked: 3 } });
    expect([await status(c, p.id), await status(c, k.id), await status(c, q.id)]).toEqual(["REVOKED", "REVOKED", "REVOKED"]);
    expect(await status(c, pending.id)).toBe("PENDING_SIGNATURE");

    // Своя запись MANDATE_REVOKED у CART (иначе — отзыв свёрткой родителя без события) и событие по каждому мандату.
    const entries = await chainOf(store, p.id);
    const revoked = entries.filter((e) => e.kind === "MANDATE_REVOKED").map((e) => e.ref);
    expect(revoked, "CART отзывается раньше корня (РП46 (а) п. 4 (iii))").toEqual([k.id, p.id]);
    const ev = (await c.consent.events(A, undefined, 100)).filter((e) => e.type === "mandate.revoked").map((e) => e.data.mandate_id);
    expect(ev).toEqual(expect.arrayContaining([k.id, p.id, q.id]));
    expect(ev.indexOf(k.id)).toBeLessThan(ev.indexOf(p.id));

    // В записи — запись банка с подписью: проверяется без банка (выписка, РП38 п. 7).
    const payload = entries.find((e) => e.kind === "MANDATE_REVOKED" && e.ref === p.id)!.payload as {
      mandate_id: string;
      revoke_all: ReturnType<typeof record>;
    };
    expect(payload.mandate_id).toBe(p.id);
    const { signature, ...rec } = payload.revoke_all;
    expect(signature).toBe(c.emu.signPrincipalRevocation(rec));
  });

  it("повтор того же revocation_ref — 200, revoked 0, новых записей и меток нет", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const p = await mk(c);
    await decide(c, p);
    expect((await revokeAll(c)).body.revoked).toBe(1);
    const before = (await chainOf(store, p.id)).length;
    expect(await revokeAll(c)).toEqual({ status: 200, body: { principal_ref: "prn_7f3c9a", revocation_ref: "rva-0001", revoked: 0 } });
    expect((await chainOf(store, p.id)).length).toBe(before);
    expect((await store.pairPosition({ participant_code: c.emu.participant_code, principal_ref: "prn_7f3c9a" }, p.id)).mark).toBe(2);
  });

  it("подпись после метки — новое согласие клиента: ACTIVE (порядок по номеру, не по часам)", async () => {
    const c = setup();
    const before = await mk(c);
    await decide(c, before);
    const pendingAtMark = await mk(c, intent({ subject: "сыр" }));
    expect((await revokeAll(c)).body.revoked).toBe(1);
    expect(await status(c, before.id)).toBe("REVOKED");
    // Мандат, запрошенный до метки и подписанный после неё, и новый мандат — действуют.
    expect(await decide(c, pendingAtMark)).toBe(200);
    const after = await mk(c, intent({ subject: "хлеб" }));
    expect(await decide(c, after)).toBe(200);
    expect([await status(c, pendingAtMark.id), await status(c, after.id)]).toEqual(["ACTIVE", "ACTIVE"]);
  });

  it("метка действует сразу, до записей (сбой посередине — 503): GET, verify и ADP — REVOKED; повтор дописывает записи", async () => {
    const inner = new MemoryConsentStore();
    let failRevoked = true;
    const store: ConsentStore = new Proxy(inner, {
      get(t, p, r) {
        if (p !== "journalWithEvent") return Reflect.get(t, p, r) as unknown;
        return (chain: string, draft: Parameters<ConsentStore["journalWithEvent"]>[1], sign?: Parameters<ConsentStore["journalWithEvent"]>[2]) => {
          const j = t.journalWithEvent(chain, draft, sign);
          if (draft.type !== "mandate.revoked") return j;
          const out: AsyncJournalStore = {
            ...(j.genesis !== undefined ? { genesis: j.genesis } : {}),
            last: () => j.last(),
            all: () => j.all(),
            append: async (e) => {
              if (failRevoked) throw new Error("ECONNRESET");
              return j.append(e);
            },
          };
          return out;
        };
      },
    });
    const c = setup({ store });
    const p = await mk(c);
    await decide(c, p);
    expect((await revokeAll(c)).status).toBe(503);
    expect((await chainOf(store, p.id)).some((e) => e.kind === "MANDATE_REVOKED")).toBe(false);
    expect(await status(c, p.id), "метка не прочитана при чтении мандата (РП46 (а) п. 5)").toBe("REVOKED");
    expect((await c.consent.verify(p.id, A))?.outcome).toBe("OUT_OF_SCOPE");
    expect((await c.consent.adpMandate(p.id, A))?.status, "ADP не видит метку до записей (инвариант 8)").toBe("REVOKED");
    failRevoked = false;
    expect((await revokeAll(c)).body.revoked).toBe(1);
    expect((await chainOf(store, p.id)).filter((e) => e.kind === "MANDATE_REVOKED")).toHaveLength(1);
  });

  it("CART под корнем, отозванным меткой, не подписывается — 409 MANDATE_NOT_PENDING", async () => {
    const c = setup();
    const p = await mk(c);
    await decide(c, p);
    const k = await mk(c, cart(p.id));
    await revokeAll(c);
    expect(await status(c, k.id)).toBe("REVOKED");
    const res = await c.app.inject({
      method: "POST",
      url: `/participants/v1/mandates/${k.id}/sign`,
      payload: (() => {
        const r = {
          participant_code: c.emu.participant_code,
          kid: c.emu.trustedKey.kid,
          mandate_id: k.id,
          mandate_hash: k.hash,
          decision: "SIGN" as const,
          signature_type: "simple" as const,
          signature_ref: "sig-cart",
          token_consent: true,
          signed_at: T0.toISOString(),
        };
        const { mandate_id: _m, ...rest } = r;
        void _m;
        return { ...rest, signature: c.emu.signRecord(r) };
      })(),
    });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toEqual({ code: "MANDATE_NOT_PENDING" });
  });

  it("другой клиент того же банка не затрагивается; неверная подпись — 401 без метки; тело не по форме — 400", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const other = await mk(c, intent({ principal_ref: "prn_other1" }));
    await decide(c, other);
    expect((await revokeAll(c, {}, (b) => (b.revoked_at = "2026-10-19T11:00:00Z"))).status).toBe(401);
    expect((await store.pairPosition({ participant_code: c.emu.participant_code, principal_ref: "prn_7f3c9a" }, other.id)).mark).toBeUndefined();
    expect((await revokeAll(c, {}, (b) => (b.extra = 1))).status).toBe(400);
    expect((await revokeAll(c, {}, (b) => (b.revoked_at = "вчера"))).status).toBe(400);
    expect((await revokeAll(c)).body.revoked).toBe(0);
    expect(await status(c, other.id)).toBe("ACTIVE");
  });

  it("подписанный мандат без строки SIGN (подпись до РП46) — не «метка не касается», а состояние не подтверждено", async () => {
    const store = new MemoryConsentStore();
    const c = setup({ store });
    const p = await mk(c);
    const row = (await store.getMandate(p.id))!;
    const { AsyncHashChainJournal } = await import("@kuzin4u/agentic-core");
    await new AsyncHashChainJournal(store.journal(row.chain), () => T0.toISOString()).append("MANDATE_SIGNED", p.id, { participant_code: "bank:test" }, p.id);
    await expect(c.consent.get(p.id, A)).rejects.toThrow(/строки SIGN/);
    // Тот же мандат со строкой SIGN — действует.
    const q = await mk(c, intent({ subject: "хлеб" }));
    await signDirect(store, q.id, T0);
    expect(await status(c, q.id)).toBe("ACTIVE");
    expect(canonicalJson(await store.pairSigns({ participant_code: "bank:test", principal_ref: "prn_7f3c9a" }, 100))).toBe(
      canonicalJson([{ mandate_id: q.id, n: 1 }]),
    );
  });
});
