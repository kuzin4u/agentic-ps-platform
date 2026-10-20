// revoke-all против подписи на двух экземплярах PostgreSQL (PS-20 ч. 2 К1.3, РП46 (а); КТ3): порядок «подпись ↔ метка»
// задаёт лок пары в базе и номер под ним, часы экземпляров не участвуют. Часы расходятся на 20 минут: подписывающий
// экземпляр «впереди», отзывающий — «позади». Управляемая пауза — внутри транзакции подписи (после строки SIGN, до COMMIT)
// или метки (после лока пары, до вставки). В CI (РП30 п. 7); локально без базы — пропуск.
import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgConsentStore, type PgConsentStoreHooks } from "../../src/consent/store.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { A, decide, intent, mk, setup, T0, type Ctx } from "../support/state.js";

const AHEAD = () => new Date(T0.getTime() + 10 * 60_000);
const BEHIND = () => new Date(T0.getTime() - 10 * 60_000);
const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

function gate() {
  let open!: () => void;
  const p = new Promise<void>((r) => (open = r));
  return { wait: () => p, open };
}

/** Промис с флагом «завершён» — блокировка на локе пары видна как незавершённый вызов. */
function track<T>(p: Promise<T>) {
  const t = { done: false, value: p };
  void p.finally(() => (t.done = true)).catch(() => undefined);
  return t;
}

async function revokeAll(c: Ctx, principal_ref: string, revocation_ref: string) {
  const r = { participant_code: c.emu.participant_code, kid: c.emu.trustedKey.kid, principal_ref, revocation_ref, revoked_at: BEHIND().toISOString() };
  const { principal_ref: _p, ...body } = { ...r, signature: c.emu.signPrincipalRevocation(r) };
  void _p;
  const res = await c.app.inject({ method: "POST", url: `/participants/v1/principals/${principal_ref}/revoke-all`, payload: body });
  return { status: res.statusCode, body: res.json() as { revoked?: number; code?: string } };
}

describe.skipIf(!DATABASE_URL)("revoke-all ↔ подпись на двух экземплярах PG с расходящимися часами (РП46 (а), КТ3)", () => {
  let db: TestDb;
  let c1: Ctx;
  let c2: Ctx;
  let store1: PgConsentStore;
  // Пауза подписи на экземпляре 1 и метки на экземпляре 2 — включаются тестом.
  let onSign: (() => Promise<void>) | undefined;
  let onMark: (() => Promise<void>) | undefined;

  beforeAll(async () => {
    db = await openTestDb("revoke_all");
    const emu = createIssuerEmulator();
    const h1: PgConsentStoreHooks = {
      inTx: async (step, draft) => {
        if (step === "commit" && draft.type === "mandate.signed" && onSign) {
          const f = onSign;
          onSign = undefined;
          await f();
        }
      },
    };
    const h2: PgConsentStoreHooks = {
      inMarkTx: async () => {
        if (onMark) {
          const f = onMark;
          onMark = undefined;
          await f();
        }
      },
    };
    store1 = new PgConsentStore(db.pool, h1);
    c1 = setup({ store: store1, now: AHEAD, emu });
    c2 = setup({ store: new PgConsentStore(db.reopen(), h2), now: BEHIND, emu });
  });
  afterAll(async () => {
    await c1?.app.close();
    await c2?.app.close();
    await db?.close();
  });

  it("подпись зафиксирована до метки (метка ждёт лока пары) — мандат REVOKED на обоих экземплярах, хотя часы подписи позже", async () => {
    const prn = "prn_race_a";
    const m = await mk(c1, intent({ principal_ref: prn }));
    const reached = gate();
    const release = gate();
    onSign = async () => {
      reached.open();
      await release.wait();
    };
    const sign = track(decide(c1, m));
    await reached.wait();
    const rev = track(revokeAll(c2, prn, "rva-race-a"));
    await tick(300);
    expect(rev.done, "метка записана, пока подпись держит лок пары (порядок фиксации не соблюдён)").toBe(false);
    release.open();
    expect(await sign.value).toBe(200);
    const r = await rev.value;
    expect(r, "revoke-all не дождался фиксации подписи под локом пары").toEqual({ status: 200, body: { principal_ref: prn, revocation_ref: "rva-race-a", revoked: 1 } });
    expect((await c1.consent.get(m.id, A))?.status, "мандат, подписанный в гонке до метки, остался ACTIVE (экземпляр подписи)").toBe("REVOKED");
    expect((await c2.consent.get(m.id, A))?.status, "мандат, подписанный в гонке до метки, остался ACTIVE (экземпляр отзыва)").toBe("REVOKED");
    expect((await c2.consent.adpMandate(m.id, A))?.status).toBe("REVOKED");
  });

  it("метка зафиксирована до подписи (подпись ждёт лока пары) — подпись после метки: новое согласие, ACTIVE; часы метки раньше", async () => {
    const prn = "prn_race_b";
    const old = await mk(c1, intent({ principal_ref: prn }));
    expect(await decide(c1, old)).toBe(200);
    const m = await mk(c1, intent({ principal_ref: prn, subject: "хлеб" }));
    const reached = gate();
    const release = gate();
    onMark = async () => {
      reached.open();
      await release.wait();
    };
    const rev = track(revokeAll(c2, prn, "rva-race-b"));
    await reached.wait();
    const sign = track(decide(c1, m));
    await tick(300);
    expect(sign.done, "подпись записана, пока метка держит лок пары").toBe(false);
    release.open();
    expect((await rev.value).body.revoked, "отозван не тот набор: до метки подписан ровно один мандат").toBe(1);
    expect(await sign.value).toBe(200);
    expect((await c2.consent.get(old.id, A))?.status).toBe("REVOKED");
    expect((await c2.consent.get(m.id, A))?.status, "подпись после метки отозвана — номер в паре не по порядку фиксации").toBe("ACTIVE");
  });

  it("лок пары, затем агента (РП46 доп. п. 5): подписи двух агентов одного клиента и одного агента двух клиентов одновременно — без взаимной блокировки", async () => {
    const agents = [A, "nspk:agent:state-b:v1"];
    const clients = ["prn_lock_x", "prn_lock_y"];
    const ms: { id: string; hash: string }[] = [];
    for (const agent of agents)
      for (const principal_ref of clients)
        for (let i = 0; i < 3; i++) {
          const k = createHash("sha256").update(randomUUID()).digest("hex");
          const m = await c1.consent.request(agent, k, intent({ principal_ref, subject: `товар ${i}` }));
          ms.push({ id: m.id!, hash: m.hash! });
        }
    // Половина — с экземпляра 1, половина — с экземпляра 2; обратный порядок локов дал бы взаимную блокировку
    // (40P01 от PostgreSQL) или зависание — предел времени ловит оба исхода.
    const all = Promise.all(ms.map((m, i) => decide(i % 2 ? c1 : c2, m)));
    const limit = new Promise<"timeout">((r) => setTimeout(() => r("timeout"), 15_000));
    const out = await Promise.race([all, limit]);
    expect(out, "подписи не завершились за 15 с — взаимная блокировка локов пары и агента").not.toBe("timeout");
    expect(out, "подпись отклонена — сбой при одновременных локах пары и агента").toEqual(ms.map(() => 200));
    for (const principal_ref of clients) {
      const signs = await store1.pairSigns({ participant_code: c1.emu.participant_code, principal_ref }, 1_000);
      expect(signs.map((x) => x.n), "номера в паре не подряд — номер выдан без лока пары").toEqual([1, 2, 3, 4, 5, 6]);
    }
  }, 20_000);

  it("CART под корнем: метка зафиксирована раньше подписи CART — CART не подписывается (409), не ACTIVE", async () => {
    const prn = "prn_race_c";
    const p = await mk(c1, intent({ principal_ref: prn }));
    expect(await decide(c1, p)).toBe(200);
    const k = await mk(c1, {
      type: "CART",
      parent_id: p.id,
      subject: "молоко 2 л",
      amount_limit: 12_900,
      currency: "RUB",
      valid_to: "2026-10-24T10:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: prn,
      mode: "IMMEDIATE",
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: 12_900 }], total: 12_900 },
    });
    const reached = gate();
    const release = gate();
    onMark = async () => {
      reached.open();
      await release.wait();
    };
    const rev = track(revokeAll(c2, prn, "rva-race-c"));
    await reached.wait();
    const sign = track(decide(c1, k));
    await tick(300);
    expect(sign.done, "подпись CART записана, пока метка держит лок пары").toBe(false);
    release.open();
    expect((await rev.value).status).toBe(200);
    expect(await sign.value, "CART подписан под корнем, отозванным меткой").toBe(409);
    expect((await c1.consent.get(k.id, A))?.status).toBe("REVOKED");
  });
});
