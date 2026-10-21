// ADP п. 2 и 4 с агентским токеном (PS-14 К1.3б, РП47 п. 6–8): домен токена, криптограмма, предел инструмента,
// погашение ISSUED → USED только у APPROVE после резерва; одноразовость при гонке; на настоящем журнале и П3 в памяти.
import { describe, expect, it } from "vitest";
import { Adp, MemoryOperationStore, type AdpCredentials, type AdpMandates, type AdpOptions } from "../../src/adp/index.js";
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
  /** ADP с теми же журналом, П3 и записями операций, но своим портом П5 или журналом согласий. */
  adpWith: (over: Partial<Pick<AdpOptions, "credentials" | "mandates" | "agents">>) => Adp;
  /** Число вызовов резерва счетов мандата (П3): тест различает «зарезервировал и освободил» и «отказал до резерва». */
  reserves: () => number;
  /** Записи операций ADP: признаки уведомителя (limit_source). */
  records: MemoryOperationStore;
}

/**
 * Подделка порта П5 делегированием, а не Object.create: у MemoryCredentialStore закрытые поля (#), через прототип они
 * не наследуются — унаследованный метод бросает TypeError, и тест проходил бы на чужой ветке (ревью КТ1 Б1).
 */
const delegate = (s: CredentialStore, over: Partial<AdpCredentials> = {}): AdpCredentials => ({
  tokenByRef: (t) => s.tokenByRef(t),
  credentialByCryptogram: (t, h) => s.credentialByCryptogram(t, h),
  consume: (c, o) => s.consume(c, o),
  ...over,
});

async function world(
  opts: { cartLimit?: number; confirmAbove?: number; clientPerPeriod?: number; phase?: 1 | 2 | 3 } = {},
): Promise<World> {
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
  const store = new MemoryCredentialStore();
  const credentials = new Credentials({
    mandates: { get: (id, code) => c.consent.credentialMandate(id, code) },
    store,
    tsp: createTokenServiceEmulator(),
    funding: c.emu,
    params: { cryptogram_ttl_sec: 900 },
    now: () => new Date(now),
  });
  const logs: string[] = [];
  // Лимит клиента за период (РП45 п. 1): запись банка до начала периода — действует сразу.
  const versions =
    opts.clientPerPeriod === undefined
      ? []
      : [{ limits: { per_period: opts.clientPerPeriod, period: "DAY", currency: "RUB" }, received_at: "2026-10-18T00:00:00Z" }];
  let reserves = 0;
  const records = new MemoryOperationStore();
  const state: AdpOptions["state"] = {
    reserve: (...a) => (reserves++, c.state.reserve(...a)),
    reserveClient: (...a) => c.state.reserveClient(...a),
    release: (...a) => c.state.release(...a),
    hold: (...a) => c.state.hold(...a),
    amountLeft: (...a) => c.state.amountLeft(...a),
    clientLeft: (...a) => c.state.clientLeft(...a),
  };
  const adpOpts: AdpOptions = {
    agents: { get: (code) => (code === A || code === B ? { status: "ACTIVE", level: 2 } : undefined) },
    mandates: { get: (id, a) => c.consent.adpMandate(id, a) },
    clientLimits: { get: async () => versions },
    state,
    operations: records,
    credentials: store,
    params: {
      aoi_rollout_phase: opts.phase ?? 3,
      confirm_above_kop: opts.confirmAbove ?? 1_000_000,
      split_window_sec: 600,
      split_min_ops: 100,
      client_limit_period_tz: "Europe/Moscow",
    },
    log: (_l, fields, msg) => logs.push(`${msg} ${JSON.stringify(fields)}`),
    now: () => new Date(now),
  };
  const adp = new Adp(adpOpts);
  const issue = async (order_ref = "ORD-1", amount_max = limit): Promise<Credential> => {
    const r = await credentials.issue(A, { mandate_id: cart.id, order_ref, merchant_id: "MER-1042", amount_max, currency: "RUB", kind: "CARD" });
    if (!r.ok) throw new Error(`реквизит не выдан: ${r.code}`);
    return r.credential;
  };
  const adpWith = (over: Partial<Pick<AdpOptions, "credentials" | "mandates" | "agents">>) => new Adp({ ...adpOpts, ...over });
  return { c, store, adp, parent: p.id, cart: cart.id, issue, logs, setNow: (t) => (now = t), adpWith, reserves: () => reserves, records };
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
    // Проигравшая прошла п. 4 и резерв и проиграла именно на погашении (ревью КТ1 З5 (б)).
    expect(w.logs.filter((l) => l.startsWith("ADP: криптограмма уже погашена другой авторизацией"))).toHaveLength(1);
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

  it("сумма > amount_max — LIMIT_EXCEEDED (меньшее из инструмента и мандата, A3 п. 7.2); другая валюта — MANDATE_SCOPE на п. 6; реквизит не погашен", async () => {
    const w = await world();
    const cred = await w.issue("ORD-1", 15_000);
    const over = auth(w, cred, {}, 15_001);
    expect(await reason(w, over)).toBe("LIMIT_EXCEEDED");
    // Чей предел — инструмента: client.limit_declined с reason INSTRUMENT (РП49 (е)).
    expect(w.records.get(over.op_ref)?.notify?.limit_source).toBe("INSTRUMENT");
    // Валюта реквизита всегда = валюте CART (РП47 п. 4): другую валюту отсекает п. 6, условие п. 7 — страховка (ревью КТ1 Б2).
    expect(await reason(w, auth(w, cred, { currency: "USD" }, 1_000))).toBe("MANDATE_SCOPE");
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

  it("сбой погашения после резерва — освобождены все удержания (CART, родитель, лимит клиента), STATE_UNAVAILABLE, реквизит ISSUED", async () => {
    const w = await world({ clientPerPeriod: 25_000 });
    const cred = await w.issue();
    const adp = w.adpWith({ credentials: delegate(w.store, { consume: () => Promise.reject(new Error("db")) }) });
    expect(parseDecision(await adp.decide(auth(w, cred, {}, 20_000)), "adp").reason).toBe("STATE_UNAVAILABLE");
    // Дошли до погашения (резерв был), а не упали раньше.
    expect(w.logs.filter((l) => l.startsWith("ADP: погашение реквизита не записано"))).toHaveLength(1);
    expect(await left(w, w.cart)).toBe(30_000);
    expect(await left(w, w.parent)).toBe(50_000);
    expect(await status(w)).toBe("ISSUED");
    // Удержание лимита клиента освобождено: весь лимит снова доступен той же криптограмме.
    expect(parseDecision(await w.adp.decide(auth(w, cred, {}, 25_000)), "adp").decision).toBe("APPROVE");
  });

  it("сбой чтения токена (п. 2) или записи реквизита (п. 4) — STATE_UNAVAILABLE до резерва", async () => {
    const w = await world();
    const cred = await w.issue();
    const byToken = w.adpWith({ credentials: delegate(w.store, { tokenByRef: () => Promise.reject(new Error("db")) }) });
    expect(parseDecision(await byToken.decide(auth(w, cred)), "adp").reason).toBe("STATE_UNAVAILABLE");
    expect(w.logs.filter((l) => l.startsWith("ADP: запись токена не прочитана"))).toHaveLength(1);
    const byCred = w.adpWith({ credentials: delegate(w.store, { credentialByCryptogram: () => Promise.reject(new Error("db")) }) });
    expect(parseDecision(await byCred.decide(auth(w, cred)), "adp").reason).toBe("STATE_UNAVAILABLE");
    expect(w.logs.filter((l) => l.startsWith("ADP: запись реквизита не прочитана"))).toHaveLength(1);
    expect(await left(w, w.cart)).toBe(30_000);
  });

  it("гонка с лимитом клиента: проигравшая на погашении освобождает и удержание лимита клиента", async () => {
    const w = await world({ clientPerPeriod: 25_000 });
    const cred = await w.issue();
    const ds = await Promise.all([w.adp.decide(auth(w, cred, {}, 10_000)), w.adp.decide(auth(w, cred, {}, 10_000))]);
    expect(ds.map((d) => d.decision).sort()).toEqual(["APPROVE", "DECLINE"]);
    expect(w.logs.filter((l) => l.startsWith("ADP: криптограмма уже погашена другой авторизацией"))).toHaveLength(1);
    // Остаток клиента — 15 000: второй реквизит на 15 000 одобряется, только если удержание проигравшей освобождено.
    const next = await w.issue("ORD-2", 15_000);
    expect(parseDecision(await w.adp.decide(auth(w, next, {}, 15_000)), "adp").decision).toBe("APPROVE");
  });

  it("отзыв между резервом и сверкой статуса (п. 12) — освобождение, MANDATE_REVOKED, реквизит не погашен", async () => {
    const w = await world();
    const cred = await w.issue();
    let calls = 0;
    const mandates: AdpMandates = {
      async get(id, a) {
        const m = await w.c.consent.adpMandate(id, a);
        // Второе чтение CART — сверка п. 12 (первое — п. 5; родитель читается своим id).
        return m && id === w.cart && ++calls === 2 ? { ...m, status: "REVOKED" } : m;
      },
    };
    expect(parseDecision(await w.adpWith({ mandates }).decide(auth(w, cred)), "adp").reason).toBe("MANDATE_REVOKED");
    // Отказ — после резерва (CART и родитель), а не до него (повторный проход ревью КТ1, п. 1).
    expect(w.reserves()).toBe(2);
    expect(await status(w)).toBe("ISSUED");
    expect(await left(w, w.cart)).toBe(30_000);
    expect(await left(w, w.parent)).toBe(50_000);
  });

  it("отказ резерва по бюджету — реквизит не погашен (ISSUED)", async () => {
    const w = await world();
    expect(parseDecision(await w.adp.decide(auth(w, await w.issue("ORD-1"), {}, 20_000)), "adp").decision).toBe("APPROVE");
    const second = await w.issue("ORD-2");
    const before = w.reserves();
    expect(await reason(w, auth(w, second, {}, 20_000))).toBe("LIMIT_EXCEEDED");
    // Отказ — на резерве счёта CART (повторный проход ревью КТ1, п. 2).
    expect(w.reserves() - before).toBe(1);
    expect(await status(w, "ORD-2")).toBe("ISSUED");
  });

  it("мандат домена токена не CART (запись токена с INTENT) — STATE_UNAVAILABLE и инцидент до статуса и резерва (РП49 (б))", async () => {
    const w = await world();
    const cred = await w.issue();
    // Запись токена испорчена: в домене — родитель INTENT (обычным путём недостижимо, РП47 п. 2).
    const credentials = delegate(w.store, { tokenByRef: async (t) => ((r) => r && { ...r, mandate_id: w.parent })(await w.store.tokenByRef(t)) });
    const m = auth(w, cred, { aoi: { indicator: true, agent_code: A, mandate_id: w.parent } });
    expect(parseDecision(await w.adpWith({ credentials }).decide(m), "adp").reason).toBe("STATE_UNAVAILABLE");
    // Клиент мандата из испорченной записи токена в запись операции не попадает: notify нет («Нюансы РП49» п. 2).
    expect(w.records.get(m.op_ref)?.notify).toBeUndefined();
    // До статуса: отозванный INTENT даёт ту же причину, а не MANDATE_REVOKED.
    const mandates: AdpMandates = {
      async get(id, a) {
        const r = await w.c.consent.adpMandate(id, a);
        return r && id === w.parent ? { ...r, status: "REVOKED" } : r;
      },
    };
    const m2 = auth(w, cred, { aoi: { indicator: true, agent_code: A, mandate_id: w.parent } });
    expect(parseDecision(await w.adpWith({ credentials, mandates }).decide(m2), "adp").reason).toBe("STATE_UNAVAILABLE");
    const incidents = w.logs.filter((l) => l.startsWith("ADP: мандат домена токена не CART") && l.includes('"incident":true'));
    expect(incidents).toHaveLength(2);
    expect(incidents.join("\n")).not.toContain(cred.payload.token_ref as string);
    expect(w.reserves()).toBe(0);
    expect(await status(w)).toBe("ISSUED");
    expect(await left(w, w.parent)).toBe(50_000);
  });

  it("AGENT_TOKEN с aoi без mandate_id — AOI_MISMATCH на п. 2 (мандат признака ≠ домену), не MANDATE_NOT_FOUND", async () => {
    const w = await world();
    const cred = await w.issue();
    expect(await reason(w, auth(w, cred, { aoi: { indicator: true, agent_code: A } as CanonicalMessage["aoi"] }))).toBe("AOI_MISMATCH");
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

describe("ADP: агентский токен без aoi — по домену токена при очереди 1–2 (РП48 (г), РП22 п. 6)", () => {
  const noAoi = (w: World, cred: Credential, over: Partial<CanonicalMessage> = {}, amount = 20_000): CanonicalMessage => {
    const m = auth(w, cred, over, amount);
    delete m.aoi;
    return m;
  };

  it.each([1, 2] as const)("очередь %i: агент и мандат — из записи токена; APPROVE, резерв CART и родителя, реквизит погашен", async (phase) => {
    const w = await world({ phase });
    const cred = await w.issue();
    const m = noAoi(w, cred);
    expect(parseDecision(await w.adp.decide(m), "adp").decision).toBe("APPROVE");
    expect(await left(w, w.cart)).toBe(10_000);
    expect(await left(w, w.parent)).toBe(30_000);
    expect(await w.store.credentialByOrder(A, w.cart, "ORD-1")).toMatchObject({ status: "USED", op_ref: m.op_ref });
    // Однократность — та же, что с признаком: вторая авторизация той же криптограммой без резерва.
    expect(await reason(w, noAoi(w, cred, {}, 5_000))).toBe("CREDENTIAL_INVALID");
    expect(await left(w, w.cart)).toBe(10_000);
  });

  it("очередь 2: мандат домена токена не CART — STATE_UNAVAILABLE и инцидент без резерва (РП49 (б))", async () => {
    const w = await world({ phase: 2 });
    const cred = await w.issue();
    const credentials = delegate(w.store, { tokenByRef: async (t) => ((r) => r && { ...r, mandate_id: w.parent })(await w.store.tokenByRef(t)) });
    expect(parseDecision(await w.adpWith({ credentials }).decide(noAoi(w, cred)), "adp").reason).toBe("STATE_UNAVAILABLE");
    const incidents = w.logs.filter((l) => l.startsWith("ADP: мандат домена токена не CART") && l.includes('"incident":true'));
    expect(incidents).toHaveLength(1);
    expect(incidents.join("\n")).not.toContain(cred.payload.token_ref as string);
    expect(w.reserves()).toBe(0);
    expect(await status(w)).toBe("ISSUED");
  });

  it("очередь 3 — AOI_MISSING до токена и резерва; реквизит не погашен", async () => {
    const w = await world({ phase: 3 });
    const cred = await w.issue();
    expect(await reason(w, noAoi(w, cred))).toBe("AOI_MISSING");
    expect(w.reserves()).toBe(0);
    expect(await status(w)).toBe("ISSUED");
  });

  it("очередь 2: токена нет, криптограммы нет или она чужая — CREDENTIAL_INVALID без резерва", async () => {
    const w = await world({ phase: 2 });
    const cred = await w.issue();
    const other = await w.issue("ORD-2", 10_000);
    expect(await reason(w, noAoi(w, cred, { instrument: { kind: "AGENT_TOKEN", token_ref: "tok_unknown", cryptogram: "x" } }))).toBe("CREDENTIAL_INVALID");
    expect(await reason(w, noAoi(w, cred, { instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string } }))).toBe("CREDENTIAL_INVALID");
    expect(
      await reason(w, noAoi(w, cred, { instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: "x" } })),
    ).toBe("CREDENTIAL_INVALID");
    // Криптограмма другого заказа того же токена — свой реквизит: сумма 20 000 > amount_max 10 000 — предел инструмента.
    expect(await reason(w, noAoi(w, other))).toBe("LIMIT_EXCEEDED");
    expect(await status(w)).toBe("ISSUED");
  });

  it("очередь 2: ACCOUNT_LINK без aoi — CREDENTIAL_INVALID до PS-21", async () => {
    const w = await world({ phase: 2 });
    const cred = await w.issue();
    expect(await reason(w, noAoi(w, cred, { instrument: { kind: "ACCOUNT_LINK", account_link_ref: "acl_1" } }))).toBe("CREDENTIAL_INVALID");
    expect(w.reserves()).toBe(0);
  });

  it("очередь 2: агент домена приостановлен — AGENT_SUSPENDED (реестр — по коду из домена, инвариант 5)", async () => {
    const w = await world({ phase: 2 });
    const cred = await w.issue();
    const adp = w.adpWith({ agents: { get: (code) => (code === A ? { status: "SUSPENDED", level: 2 } : undefined) } });
    expect(parseDecision(await adp.decide(noAoi(w, cred)), "adp").reason).toBe("AGENT_SUSPENDED");
    expect(await status(w)).toBe("ISSUED");
  });

  it("очередь 2: сбой чтения токена — STATE_UNAVAILABLE до резерва", async () => {
    const w = await world({ phase: 2 });
    const cred = await w.issue();
    const adp = w.adpWith({
      credentials: delegate(w.store, {
        tokenByRef: async () => {
          throw new Error("нет связи");
        },
      }),
    });
    expect(parseDecision(await adp.decide(noAoi(w, cred)), "adp").reason).toBe("STATE_UNAVAILABLE");
    expect(w.reserves()).toBe(0);
  });
});
