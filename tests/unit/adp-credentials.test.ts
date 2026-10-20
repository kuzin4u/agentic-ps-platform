// ADP п. 2 и 4 с агентским токеном (PS-14 К1.3б, РП47 п. 6–8): домен токена, криптограмма, предел инструмента,
// погашение ISSUED → USED только у APPROVE после резерва; одноразовость при гонке; на настоящем журнале и П3 в памяти.
import { describe, expect, it } from "vitest";
import { Adp, MemoryOperationStore } from "../../src/adp/index.js";
import { Credentials, MemoryCredentialStore, type CredentialStore } from "../../src/credentials/index.js";
import { createTokenServiceEmulator } from "../../src/env/tsp/index.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Credential } from "../../src/shared/pao.js";
import { accountId } from "../../src/state/index.js";
import { A, decide, intent, mk, setup, T0, type Ctx } from "../support/state.js";

const B = "nspk:agent:state-b:v1";
let seq = 0;

interface World {
  c: Ctx;
  store: CredentialStore;
  adp: Adp;
  parent: string;
  cart: string;
  issue: (order_ref?: string, amount_max?: number) => Promise<Credential>;
  logs: string[];
  setNow: (t: number) => void;
}

async function world(opts: { store?: CredentialStore; cartLimit?: number; confirmAbove?: number; adpStore?: CredentialStore } = {}): Promise<World> {
  let now = T0.getTime();
  const c = setup({ now: () => new Date(now) });
  const p = await mk(c, intent({ amount_limit: 50_000 }));
  await decide(c, p);
  const limit = opts.cartLimit ?? 30_000;
  const cart = await mk(
    c,
    intent({
      type: "CART",
      parent_id: p.id,
      subject: "корзина SHOP-1042",
      amount_limit: limit,
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk-2l", qty: 1, price: limit }], total: limit },
    }),
  );
  await decide(c, cart);
  const store = opts.store ?? new MemoryCredentialStore();
  const credentials = new Credentials({
    mandates: { get: (id, code) => c.consent.credentialMandate(id, code) },
    store,
    tsp: createTokenServiceEmulator(),
    funding: c.emu,
    params: { cryptogram_ttl_sec: 900 },
    now: () => new Date(now),
  });
  const logs: string[] = [];
  const adp = new Adp({
    agents: { get: (code) => (code === A || code === B ? { status: "ACTIVE", level: 2 } : undefined) },
    mandates: { get: (id, a) => c.consent.adpMandate(id, a) },
    clientLimits: { get: async () => [] },
    state: c.state,
    operations: new MemoryOperationStore(),
    credentials: opts.adpStore ?? store,
    params: {
      aoi_rollout_phase: 3,
      confirm_above_kop: opts.confirmAbove ?? 1_000_000,
      split_window_sec: 600,
      split_min_ops: 100,
      client_limit_period_tz: "Europe/Moscow",
    },
    log: (_l, fields, msg) => logs.push(`${msg} ${JSON.stringify(fields)}`),
    now: () => new Date(now),
  });
  const issue = async (order_ref = "ORD-1", amount_max = limit): Promise<Credential> => {
    const r = await credentials.issue(A, { mandate_id: cart.id, order_ref, merchant_id: "MER-1042", amount_max, currency: "RUB", kind: "CARD" });
    if (!r.ok) throw new Error(`реквизит не выдан: ${r.code}`);
    return r.credential;
  };
  return { c, store, adp, parent: p.id, cart: cart.id, issue, logs, setNow: (t) => (now = t) };
}

const auth = (w: World, cred: Credential, over: Partial<CanonicalMessage> = {}, amount = 20_000): CanonicalMessage => ({
  op_ref: `OPKC-CRED-${++seq}`,
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount,
  currency: "RUB",
  merchant: { id: "MER-1042" },
  instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
  aoi: { indicator: true, agent_code: A, mandate_id: w.cart },
  ...over,
});

const reason = async (w: World, m: CanonicalMessage) => parseDecision(await w.adp.decide(m), "adp").reason;
const left = async (w: World, id: string) => (await w.c.ledger.available(accountId(id))).amount;
const status = async (w: World, order_ref = "ORD-1") => (await w.store.credentialByOrder(A, w.cart, order_ref))?.status;

describe("ADP п. 2 и 4: агентский токен (РП47 п. 6–8)", () => {
  it("APPROVE: два резерва, реквизит погашен с op_ref; вторая авторизация той же криптограммой — CREDENTIAL_INVALID без резерва", async () => {
    const w = await world();
    const cred = await w.issue();
    const m = auth(w, cred);
    const d = parseDecision(await w.adp.decide(m), "adp");
    expect(d.decision).toBe("APPROVE");
    expect(await left(w, w.cart)).toBe(10_000);
    expect(await w.store.credentialByOrder(A, w.cart, "ORD-1")).toMatchObject({ status: "USED", op_ref: m.op_ref });
    expect(await reason(w, auth(w, cred, {}, 5_000))).toBe("CREDENTIAL_INVALID");
    expect(await left(w, w.cart)).toBe(10_000);
    expect(await left(w, w.parent)).toBe(30_000);
  });

  it("повтор той же авторизации по op_ref — прежнее APPROVE, второго погашения и резерва нет", async () => {
    const w = await world();
    const m = auth(w, await w.issue());
    const a = await w.adp.decide(m);
    const b = await w.adp.decide({ ...m, ts: "2026-10-19T10:00:05Z" });
    expect(parseDecision(b, "adp").decision).toBe("APPROVE");
    expect(b.reservation_id).toBe(a.reservation_id);
    expect(await left(w, w.cart)).toBe(10_000);
  });

  it("гонка: две авторизации одной криптограммой одновременно — ровно одна APPROVE, вторая CREDENTIAL_INVALID, её удержания освобождены", async () => {
    const w = await world();
    const cred = await w.issue();
    // Обе суммы помещаются в бюджет: различает только одноразовость криптограммы.
    const ds = await Promise.all([w.adp.decide(auth(w, cred, {}, 10_000)), w.adp.decide(auth(w, cred, {}, 10_000))]);
    const decisions = ds.map((d) => parseDecision(d, "adp"));
    expect(decisions.filter((d) => d.decision === "APPROVE")).toHaveLength(1);
    expect(decisions.filter((d) => d.reason === "CREDENTIAL_INVALID")).toHaveLength(1);
    expect(await left(w, w.cart)).toBe(20_000);
    expect(await left(w, w.parent)).toBe(40_000);
  });

  it("токена нет в хранилище — CREDENTIAL_INVALID; token_ref пуст — CREDENTIAL_INVALID", async () => {
    const w = await world();
    const cred = await w.issue();
    expect(await reason(w, auth(w, cred, { instrument: { kind: "AGENT_TOKEN", token_ref: "tok_ag_unknown", cryptogram: "x" } }))).toBe("CREDENTIAL_INVALID");
    expect(await reason(w, auth(w, cred, { instrument: { kind: "AGENT_TOKEN", cryptogram: "x" } }))).toBe("CREDENTIAL_INVALID");
  });

  it("код агента или мандат в aoi ≠ домену токена — AOI_MISMATCH и инцидент, до реестра; реквизит не погашен", async () => {
    const w = await world();
    const cred = await w.issue();
    expect(await reason(w, auth(w, cred, { aoi: { indicator: true, agent_code: B, mandate_id: w.cart } }))).toBe("AOI_MISMATCH");
    expect(await reason(w, auth(w, cred, { aoi: { indicator: true, agent_code: "nspk:agent:nobody:v1", mandate_id: w.cart } }))).toBe("AOI_MISMATCH");
    expect(await reason(w, auth(w, cred, { aoi: { indicator: true, agent_code: A, mandate_id: w.parent } }))).toBe("AOI_MISMATCH");
    expect(w.logs.filter((l) => l.includes("признак не совпадает с доменом токена") && l.includes('"incident":true'))).toHaveLength(3);
    expect(await status(w)).toBe("ISSUED");
  });

  it("криптограмма неверна, пуста или от другого заказа того же токена — CREDENTIAL_INVALID", async () => {
    const w = await world();
    const cred = await w.issue();
    const other = await w.issue("ORD-2");
    const token_ref = cred.payload.token_ref as string;
    expect(await reason(w, auth(w, cred, { instrument: { kind: "AGENT_TOKEN", token_ref, cryptogram: "AAAA" } }))).toBe("CREDENTIAL_INVALID");
    expect(await reason(w, auth(w, cred, { instrument: { kind: "AGENT_TOKEN", token_ref } }))).toBe("CREDENTIAL_INVALID");
    // Чужая криптограмма того же токена — своя запись реквизита: пройдёт как свой заказ, а не как ORD-1.
    expect(parseDecision(await w.adp.decide(auth(w, other)), "adp").decision).toBe("APPROVE");
    expect(await status(w, "ORD-2")).toBe("USED");
    expect(await status(w, "ORD-1")).toBe("ISSUED");
  });

  it("истёк valid_to (часы Платформы) — CREDENTIAL_INVALID", async () => {
    const w = await world();
    const cred = await w.issue();
    w.setNow(Date.parse(cred.payload.valid_to as string));
    expect(await reason(w, auth(w, cred))).toBe("CREDENTIAL_INVALID");
  });

  it("продавец ≠ продавцу реквизита — CREDENTIAL_INVALID", async () => {
    const w = await world();
    const cred = await w.issue();
    expect(await reason(w, auth(w, cred, { merchant: { id: "MER-2" } }))).toBe("CREDENTIAL_INVALID");
  });

  it("сумма > amount_max или валюта ≠ — LIMIT_EXCEEDED (меньшее из инструмента и мандата, A3 п. 7.2), реквизит не погашен", async () => {
    const w = await world();
    const cred = await w.issue("ORD-1", 15_000);
    expect(await reason(w, auth(w, cred, {}, 15_001))).toBe("LIMIT_EXCEEDED");
    expect(await reason(w, auth(w, cred, { currency: "USD" }, 1_000))).not.toBe("APPROVE");
    expect(await status(w)).toBe("ISSUED");
    expect(await left(w, w.cart)).toBe(30_000);
    expect(parseDecision(await w.adp.decide(auth(w, cred, {}, 15_000)), "adp").decision).toBe("APPROVE");
  });

  it("CONFIRMATION_REQUIRED — реквизит не погашен: тот же заказ повторяется после подтверждения (PS-19)", async () => {
    const w = await world({ confirmAbove: 10_000 });
    const cred = await w.issue();
    expect(await reason(w, auth(w, cred))).toBe("CONFIRMATION_REQUIRED");
    expect(await status(w)).toBe("ISSUED");
    expect(parseDecision(await w.adp.decide(auth(w, cred, {}, 9_000)), "adp").decision).toBe("APPROVE");
  });

  it("сбой погашения — STATE_UNAVAILABLE, удержания освобождены; сбой чтения токена или реквизита — STATE_UNAVAILABLE", async () => {
    const w = await world();
    const cred = await w.issue();
    const broken = Object.create(w.store) as CredentialStore;
    broken.consume = () => Promise.reject(new Error("db"));
    const adp = new Adp({ ...(w.adp as unknown as { opts: ConstructorParameters<typeof Adp>[0] }).opts, credentials: broken });
    expect(parseDecision(await adp.decide(auth(w, cred)), "adp").reason).toBe("STATE_UNAVAILABLE");
    expect(await left(w, w.cart)).toBe(30_000);
    expect(await left(w, w.parent)).toBe(50_000);
    expect(await status(w)).toBe("ISSUED");
    for (const method of ["tokenByRef", "credentialByCryptogram"] as const) {
      const s = Object.create(w.store) as CredentialStore;
      (s as unknown as Record<string, unknown>)[method] = () => Promise.reject(new Error("db"));
      const a = new Adp({ ...(w.adp as unknown as { opts: ConstructorParameters<typeof Adp>[0] }).opts, credentials: s });
      expect(parseDecision(await a.decide(auth(w, cred)), "adp").reason, method).toBe("STATE_UNAVAILABLE");
    }
  });

  it("в журнале процесса ADP нет token_ref и криптограммы, нет серий из 13–19 цифр (инвариант 1)", async () => {
    const w = await world();
    const cred = await w.issue();
    await w.adp.decide(auth(w, cred, { aoi: { indicator: true, agent_code: B, mandate_id: w.cart } }));
    await w.adp.decide(auth(w, cred));
    await w.adp.decide(auth(w, cred));
    const dump = w.logs.join("\n");
    expect(w.logs.length).toBeGreaterThan(0);
    expect(dump).not.toContain(cred.payload.token_ref as string);
    expect(dump).not.toContain(cred.payload.cryptogram as string);
    expect(dump).not.toMatch(/\d{13,19}/);
  });
});
