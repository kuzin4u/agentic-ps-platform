// П4 точка решения ADP (PS-10, РП43) на удержаниях ядра в памяти: BYPASS первой проверкой до ввода-вывода (инвариант 2),
// порядок проверок SPEC §6, коды П3 → ПИ (п. 3), неподтверждённое состояние — отказ (п. 4, A3 п. 4.5), резерв по op_ref и
// повтор (п. 5), сверка статуса после резерва (п. 5, РП41 п. 8). Каждое решение — согласованная пара (parseDecision, РП19).
import { AsyncMemoryHoldLedger, type AsyncHoldLedger } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import {
  Adp,
  AdpRequestInvalid,
  effectiveThreshold,
  isBypass,
  parseClientThreshold,
  MemoryOperationStore,
  STATE_TO_PI,
  STATUS_TO_PI,
  type AdpAgents,
  type AdpMandate,
  type AdpMandates,
  type ClientLimitsSource,
} from "../../src/adp/index.js";
import { ConsentIntegrityError, type MandateStatus } from "../../src/consent/model.js";
import type { AgentStatus } from "../../src/registry/model.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { DECISION_REASONS, parseDecision } from "../../src/shared/codes.js";
import { periodStart } from "../../src/participants/limits.js";
import { accountId, clientAccountId, STATE_CODES, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";

const AGENT = "nspk:agent:buyref-01:v3";
const OTHER = "nspk:agent:other-02:v1";
const M = "mnd_00000000-0000-4000-8000-000000000001";
const LIMIT = 300_000;
const THRESHOLD = 1_000_000;
/** Клиент мандата из журнала (РП45 п. 1): банк подписи корня и principal_ref. */
const CLIENT = { participant_code: "bank:a", principal_ref: "prn_7f3c9a" } as const;
/** Лимитов клиента нет: порт подключён (обязателен), записей — ни одной. */
const NO_LIMITS: ClientLimitsSource = { get: async () => [] };
/** Версия записи лимитов в истории порта: получена давно — действует в текущем периоде. */
const version = (limits: unknown, received_at = "2026-09-01T00:00:00Z") => ({ limits, received_at });

const msg = (over: Partial<CanonicalMessage> = {}): CanonicalMessage => ({
  op_ref: "OPKC-20261019-000001",
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount: 189_000,
  currency: "RUB",
  merchant: { id: "MER-1042", mcc: "5462" },
  instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
  aoi: { indicator: true, agent_code: AGENT, mandate_id: M },
  ts: "2026-10-19T10:00:00Z",
  ...over,
});
const plain = (over: Partial<CanonicalMessage> = {}): CanonicalMessage => {
  const m = msg(over);
  delete m.aoi;
  return m;
};

class Agents implements AdpAgents {
  calls = 0;
  failing = false;
  readonly map = new Map<string, AgentStatus>([[AGENT, "ACTIVE"]]);
  get(code: string) {
    this.calls++;
    if (this.failing) throw new Error("реестр недоступен");
    const status = this.map.get(code);
    return status && { status, level: 1 };
  }
}

type Row = AdpMandate & { agent_code: string };

/** Журнал согласий: мандат агента для ADP и бюджет для П3; afterReserve — подмена второго чтения (отзыв в окне). */
class Journal implements AdpMandates, MandateBudgetSource {
  calls = 0;
  failing = false;
  readonly map = new Map<string, Row>();
  /** Вызывается при каждом чтении ADP по номеру чтения; вернуть статус — подменить его. */
  onGet?: (n: number) => MandateStatus | "fail" | undefined;
  /** Исключение вместо ответа (нарушенная цепочка и т. п.). */
  throwing?: Error;
  #n = 0;
  set(id: string, over: Partial<Row> = {}): this {
    this.map.set(id, {
      agent_code: AGENT,
      status: "ACTIVE",
      type: "INTENT",
      merchant_scope: ["MER-1042"],
      currency: "RUB",
      amount_limit: LIMIT,
      client: CLIENT,
      ...over,
    });
    return this;
  }
  async get(id: string, agent_code: string): Promise<AdpMandate | undefined> {
    this.calls++;
    if (this.failing) throw new Error("журнал недоступен");
    if (this.throwing) throw this.throwing;
    const r = this.map.get(id);
    if (!r || r.agent_code !== agent_code) return undefined;
    const sub = this.onGet?.(++this.#n);
    if (sub === "fail") throw new Error("журнал недоступен");
    return sub ? { ...r, status: sub } : r;
  }
  async budget(id: string): Promise<MandateBudget | undefined> {
    if (this.failing) throw new Error("журнал недоступен");
    const r = this.map.get(id);
    return r && { status: r.status ?? "ACTIVE", amount_limit: r.amount_limit, currency: r.currency };
  }
}

/** Ядро или хранилище записей с отказом по выбору и счётчиком обращений. */
function spy<T extends object>(inner: T, broken: Set<string>, count: { n: number }): T {
  return new Proxy(inner, {
    get(t, p, r) {
      const v = Reflect.get(t, p, r) as unknown;
      if (typeof v !== "function") return v;
      return (...a: unknown[]) => {
        count.n++;
        if (broken.has(String(p))) return Promise.reject(new Error("ECONNRESET"));
        return (v as (...x: unknown[]) => unknown).apply(t, a);
      };
    },
  });
}

function setup(
  opts: { phase?: 1 | 2 | 3; client?: ClientLimitsSource; threshold?: number; splitMinOps?: number; now?: () => Date } = {},
) {
  const agents = new Agents();
  const journal = new Journal().set(M);
  const ledger = new AsyncMemoryHoldLedger();
  const broken = new Set<string>();
  const io = { n: 0 };
  const state = new StateService(spy<AsyncHoldLedger>(ledger, broken, io), journal, { reservationTtlSec: 600 });
  const records = new MemoryOperationStore();
  const operations = spy(records, broken, io);
  const logs: { fields: Record<string, unknown>; msg: string }[] = [];
  const adp = new Adp({
    agents,
    mandates: journal,
    state,
    operations,
    params: { aoi_rollout_phase: opts.phase ?? 3, confirm_above_kop: opts.threshold ?? THRESHOLD,
      split_window_sec: 600,
      split_min_ops: opts.splitMinOps ?? 2, client_limit_period_tz: "Europe/Moscow",
    },
    clientLimits: opts.client ?? NO_LIMITS,
    ...(opts.now ? { now: opts.now } : {}),
    log: (_l, fields, m) => logs.push({ fields, msg: m }),
  });
  const available = async (id = M) => (await ledger.available(accountId(id))).amount;
  return { adp, agents, journal, ledger, state, broken, io, logs, available, records };
}

/** Решение ADP — только согласованная пара (РП19); иначе parseDecision бросает. */
const pair = (d: Decision) => parseDecision(d, "adp");
const reasonOf = async (adp: Adp, m: CanonicalMessage) => pair(await adp.decide(m)).reason;

describe("BYPASS — первая проверка (РП4, РП43 п. 1, инвариант 2)", () => {
  it("нет aoi и CARD_TOKEN — BYPASS / null при сбое реестра, журнала, П3 и записи операций, без обращений к ним", async () => {
    const { adp, agents, journal, broken, io } = setup();
    agents.failing = true;
    journal.failing = true;
    for (const m of ["begin", "finish", "enterWindow", "get", "reserve", "available", "release", "account"]) broken.add(m);
    expect(pair(await adp.decide(plain()))).toEqual({ decision: "BYPASS", reason: null });
    expect([agents.calls, journal.calls, io.n]).toEqual([0, 0, 0]);
  });

  it("aoi: null — как отсутствие признака: BYPASS", async () => {
    const { adp, agents } = setup();
    agents.failing = true;
    expect(pair(await adp.decide(msg({ aoi: null as unknown as undefined }))).decision).toBe("BYPASS");
  });

  it("BYPASS не зависит от остального тела: сумма, валюта, продавец, op_ref не разбираются", async () => {
    const { adp } = setup();
    const odd = { ...plain(), op_ref: "", amount: -1, currency: "??", merchant: undefined } as unknown as CanonicalMessage;
    expect(pair(await adp.decide(odd)).decision).toBe("BYPASS");
  });

  it("isBypass — только по aoi и виду инструмента", () => {
    expect(isBypass({ instrument: { kind: "CARD_TOKEN" } })).toBe(true);
    expect(isBypass({ instrument: { kind: "AGENT_TOKEN" } })).toBe(false);
    expect(isBypass({ instrument: { kind: "ACCOUNT_LINK" } })).toBe(false);
    expect(isBypass({ instrument: { kind: "CARD_TOKEN" }, aoi: { indicator: false } })).toBe(false);
  });
});

describe("признак (SPEC §6 п. 1, A1 п. 3.2, РП43 п. 2)", () => {
  it("неизвестный вид инструмента без aoi — AOI_MISSING и инцидент, не BYPASS", async () => {
    const { adp, logs } = setup();
    const d = await adp.decide(plain({ instrument: { kind: "NEW_KIND" as "CARD_TOKEN" } }));
    expect(pair(d)).toEqual({ decision: "DECLINE", reason: "AOI_MISSING" });
    expect(logs.some((l) => l.fields.incident === true)).toBe(true);
  });

  it.each(["AGENT_TOKEN", "ACCOUNT_LINK"] as const)("%s без aoi, очередь 3 — AOI_MISSING (ПС07)", async (kind) => {
    const { adp } = setup({ phase: 3 });
    expect(pair(await adp.decide(plain({ instrument: { kind } })))).toEqual({ decision: "DECLINE", reason: "AOI_MISSING" });
  });

  it.each([1, 2] as const)("AGENT_TOKEN без aoi, очередь %i — домен токена не подключён (PS-14): CREDENTIAL_INVALID", async (phase) => {
    const { adp } = setup({ phase });
    expect(await reasonOf(adp, plain({ instrument: { kind: "AGENT_TOKEN" } }))).toBe("CREDENTIAL_INVALID");
  });

  it.each([
    ["indicator: false", { indicator: false, agent_code: AGENT }],
    ["без indicator", { agent_code: AGENT }],
    ["без кода агента", { indicator: true }],
    ["код не по форме", { indicator: true, agent_code: "buyref-01" }],
  ])("%s — AOI_MISSING", async (_n, aoi) => {
    const { adp, agents } = setup();
    expect(pair(await adp.decide(msg({ aoi })))).toEqual({ decision: "DECLINE", reason: "AOI_MISSING" });
    expect(agents.calls).toBe(0);
  });

  it.each([
    ["op_ref", { op_ref: "" }],
    ["amount", { amount: 0 }],
    ["amount", { amount: 1.5 }],
    ["currency", { currency: "rub" }],
  ])("агентское сообщение с %s не по форме — AdpRequestInvalid (400, у процессинга ADP_UNAVAILABLE)", async (field, over) => {
    const { adp } = setup();
    await expect(adp.decide(msg(over))).rejects.toMatchObject({ name: "AdpRequestInvalid", field });
  });
});

describe("агент — из реестра (SPEC §6 п. 3, A1 п. 5.3, инвариант 5)", () => {
  it("нет в реестре — AGENT_UNKNOWN; EXCLUDED — AGENT_UNKNOWN; SUSPENDED — AGENT_SUSPENDED", async () => {
    const { adp, agents } = setup();
    agents.map.clear();
    expect(await reasonOf(adp, msg({ op_ref: "a" }))).toBe("AGENT_UNKNOWN");
    agents.map.set(AGENT, "EXCLUDED");
    expect(await reasonOf(adp, msg({ op_ref: "b" }))).toBe("AGENT_UNKNOWN");
    agents.map.set(AGENT, "SUSPENDED");
    expect(await reasonOf(adp, msg({ op_ref: "c" }))).toBe("AGENT_SUSPENDED");
  });

  it("сбой реестра — STATE_UNAVAILABLE, не BYPASS (РП43 п. 4)", async () => {
    const { adp, agents } = setup();
    agents.failing = true;
    expect(pair(await adp.decide(msg()))).toEqual({ decision: "DECLINE", reason: "STATE_UNAVAILABLE" });
  });

  it("неизвестный вид инструмента при aoi — CREDENTIAL_INVALID и инцидент (доп. РП43 п. 13, /audit PS-10 № 1)", async () => {
    const { adp, logs } = setup();
    expect(await reasonOf(adp, msg({ instrument: { kind: "NEW_KIND" as "CARD_TOKEN" } }))).toBe("CREDENTIAL_INVALID");
    expect(logs.some((l) => l.fields.incident === true && l.fields.kind === "NEW_KIND")).toBe(true);
  });

  it("агентский токен с aoi до PS-14 — CREDENTIAL_INVALID (проверки 2 и 4 не подтверждены, РП43 п. 7), и до реестра", async () => {
    const { adp, agents } = setup();
    agents.map.clear();
    expect(await reasonOf(adp, msg({ instrument: { kind: "AGENT_TOKEN", token_ref: "tok_ag_1" } }))).toBe("CREDENTIAL_INVALID");
  });
});

describe("мандат и область (SPEC §6 п. 5–6, РП43 п. 2–3)", () => {
  it("нет mandate_id, неизвестный, чужой — MANDATE_NOT_FOUND", async () => {
    const { adp, journal } = setup();
    journal.set("mnd_other", { agent_code: OTHER });
    expect(await reasonOf(adp, msg({ op_ref: "a", aoi: { indicator: true, agent_code: AGENT } }))).toBe("MANDATE_NOT_FOUND");
    expect(await reasonOf(adp, msg({ op_ref: "b", aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_x" } }))).toBe(
      "MANDATE_NOT_FOUND",
    );
    expect(await reasonOf(adp, msg({ op_ref: "c", aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_other" } }))).toBe(
      "MANDATE_NOT_FOUND",
    );
  });

  it.each(Object.entries(STATUS_TO_PI))("статус %s — %s, резерва нет", async (status, reason) => {
    const { adp, journal, available } = setup();
    journal.set(M, { status: status as MandateStatus });
    expect(await reasonOf(adp, msg())).toBe(reason);
    await expect(available()).rejects.toThrow();
  });

  it("статус вне перечня (данные, не тип) — STATE_UNAVAILABLE, не «действует» (инвариант 3)", async () => {
    const { adp, journal, available } = setup();
    journal.set(M, { status: "FROZEN" as MandateStatus });
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    await expect(available()).rejects.toThrow();
  });

  it("тип мандата вне перечня — STATE_UNAVAILABLE, не резерв «как INTENT» (/audit PS-10 № 2)", async () => {
    const { adp, journal, available } = setup();
    journal.set(M, { type: "SUBSCRIPTION" as "INTENT" });
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    await expect(available()).rejects.toThrow();
  });

  it("нарушенная цепочка журнала — STATE_UNAVAILABLE и инцидент (РП43 п. 4, /audit PS-10 № 3)", async () => {
    const { adp, journal, logs } = setup();
    journal.throwing = new ConsentIntegrityError(M, "цепочка нарушена");
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(logs.some((l) => l.fields.incident === true && l.msg.includes("журнал согласий"))).toBe(true);
  });

  it("сбой журнала — STATE_UNAVAILABLE, не BYPASS (РП43 п. 4)", async () => {
    const { adp, journal } = setup();
    journal.failing = true;
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
  });

  it("продавец вне merchant_scope, без merchant.id, валюта не мандата — MANDATE_SCOPE", async () => {
    const { adp } = setup();
    expect(await reasonOf(adp, msg({ op_ref: "a", merchant: { id: "MER-77" } }))).toBe("MANDATE_SCOPE");
    expect(await reasonOf(adp, msg({ op_ref: "b", merchant: {} }))).toBe("MANDATE_SCOPE");
    expect(await reasonOf(adp, msg({ op_ref: "c", currency: "USD" }))).toBe("MANDATE_SCOPE");
  });

  it("CART без parent_id или без родителя в журнале — STATE_UNAVAILABLE, не APPROVE по счёту CART (РП43 п. 6)", async () => {
    const { adp, journal, available } = setup();
    journal.set(M, { type: "CART" });
    expect(await reasonOf(adp, msg({ op_ref: "a" }))).toBe("STATE_UNAVAILABLE");
    journal.set(M, { type: "CART", parent_id: "mnd_parent" });
    expect(await reasonOf(adp, msg({ op_ref: "b" }))).toBe("STATE_UNAVAILABLE");
    await expect(available()).rejects.toThrow();
  });

  it("CART: сбой резерва на родителе — STATE_UNAVAILABLE, резерв CART освобождён", async () => {
    const { adp, journal, available, ledger } = setup();
    const P = "mnd_00000000-0000-4000-8000-0000000000aa";
    journal.set(P);
    journal.set(M, { type: "CART", parent_id: P, amount_limit: 200_000 });
    const reserve = ledger.reserve.bind(ledger);
    ledger.reserve = (...a) => (a[0] === accountId(P) ? Promise.reject(new Error("ECONNRESET")) : reserve(...a));
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(await available()).toBe(200_000);
  });

  it("CART: отзыв в окне резерва — оба удержания освобождены", async () => {
    const { adp, journal, available } = setup();
    const P = "mnd_00000000-0000-4000-8000-0000000000aa";
    journal.set(P);
    journal.set(M, { type: "CART", parent_id: P, amount_limit: 200_000 });
    journal.onGet = (n) => (n === 3 ? "REVOKED" : undefined);
    expect(await reasonOf(adp, msg())).toBe("MANDATE_REVOKED");
    expect([await available(), await available(P)]).toEqual([200_000, LIMIT]);
  });

  it("сумма выше порога — CONFIRMATION_REQUIRED со split_detected: false; с confirmation_ref до PS-19 — то же (РП44 п. 6–7)", async () => {
    const { adp, journal } = setup();
    journal.set(M, { amount_limit: 2 * THRESHOLD });
    const d = await adp.decide(msg({ op_ref: "a", amount: THRESHOLD + 1 }));
    expect(pair(d)).toEqual({ decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED" });
    expect(d.split_detected).toBe(false);
    const r = await adp.decide(msg({ op_ref: "b", amount: THRESHOLD + 1, confirmation_ref: "cnf_1" }));
    expect([pair(r).reason, r.split_detected]).toEqual(["CONFIRMATION_REQUIRED", false]);
  });

  it("у APPROVE и DECLINE поля split_detected нет (РП44 п. 7)", async () => {
    const { adp, agents } = setup();
    expect(await adp.decide(msg({ op_ref: "a" }))).not.toHaveProperty("split_detected");
    agents.map.set(AGENT, "SUSPENDED");
    expect(await adp.decide(msg({ op_ref: "b" }))).not.toHaveProperty("split_detected");
  });

  it("сумма выше порога и выше остатка — LIMIT_EXCEEDED (проверки 7–8 раньше 9–10), резерва нет", async () => {
    const { adp, available } = setup();
    expect(await reasonOf(adp, msg({ amount: THRESHOLD + 1 }))).toBe("LIMIT_EXCEEDED");
    await expect(available()).rejects.toThrow();
  });
});

describe("меньшее из порогов (SPEC §6 п. 10, РП44 п. 5, A3 п. 7.2)", () => {
  const client = (v: unknown | (() => never)): ClientLimitsSource & { calls: number } => {
    const port = {
      calls: 0,
      async get() {
        port.calls++;
        return typeof v === "function" ? (v as () => never)() : v === undefined ? [] : [version(v)];
      },
    };
    return port;
  };

  it("клиентский ниже рыночного — действует клиентский: CONFIRMATION_REQUIRED без резерва", async () => {
    const { adp, available } = setup({ client: client({ confirm_above: 100_000, currency: "RUB" }) });
    const d = await adp.decide(msg());
    expect([pair(d).reason, d.split_detected]).toEqual(["CONFIRMATION_REQUIRED", false]);
    await expect(available()).rejects.toThrow();
  });

  it("клиентский выше рыночного — действует рыночный", async () => {
    const { adp, journal } = setup({ client: client({ confirm_above: 5 * THRESHOLD, currency: "RUB" }) });
    journal.set(M, { amount_limit: 2 * THRESHOLD });
    expect(await reasonOf(adp, msg({ op_ref: "a", amount: THRESHOLD + 1 }))).toBe("CONFIRMATION_REQUIRED");
    expect(pair(await adp.decide(msg({ op_ref: "b", amount: THRESHOLD }))).decision).toBe("APPROVE");
  });

  it("клиентский 0 — подтверждение любой суммы; не задан — рыночный", async () => {
    expect(await reasonOf(setup({ client: client({ confirm_above: 0, currency: "RUB" }) }).adp, msg())).toBe("CONFIRMATION_REQUIRED");
    expect(pair(await setup({ client: client(undefined) }).adp.decide(msg())).decision).toBe("APPROVE");
  });

  it("сбой порта — STATE_UNAVAILABLE без резерва (A3 п. 4.5)", async () => {
    const { adp, available } = setup({
      client: client(() => {
        throw new Error("ECONNRESET");
      }),
    });
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    await expect(available()).rejects.toThrow();
  });

  it.each([
    ["отрицательный", { confirm_above: -1, currency: "RUB" }],
    ["дробный", { confirm_above: 1.5, currency: "RUB" }],
    ["валюта не ISO 4217", { confirm_above: 100, currency: "rub" }],
    ["без валюты", { confirm_above: 100 }],
    ["число вместо записи", 100],
    ["null", null],
    ["в другой валюте", { confirm_above: 100, currency: "USD" }],
    ["неизвестное поле", { confirm_above: 100, currency: "RUB", per_week: 1 }],
  ])("запись лимитов не по форме (%s) — STATE_UNAVAILABLE", async (_n, v) => {
    expect(await reasonOf(setup({ client: client(v) }).adp, msg())).toBe("STATE_UNAVAILABLE");
  });

  it("операция не в RUB — порог не определён: STATE_UNAVAILABLE, не сравнение копеек с центами", async () => {
    const { adp, journal } = setup();
    journal.set(M, { currency: "USD" });
    expect(await reasonOf(adp, msg({ currency: "USD" }))).toBe("STATE_UNAVAILABLE");
  });

  it("неагентская — порт порога не вызывается (инвариант 2)", async () => {
    const port = client({ confirm_above: 0, currency: "RUB" });
    expect(pair(await setup({ client: port }).adp.decide(plain())).decision).toBe("BYPASS");
    expect(port.calls).toBe(0);
  });

  it("effectiveThreshold и parseClientThreshold", () => {
    const rub = (amount: number) => ({ amount, currency: "RUB" });
    expect(effectiveThreshold(rub(300_000), undefined, "RUB")).toBe(300_000);
    expect(effectiveThreshold(rub(300_000), rub(100_000), "RUB")).toBe(100_000);
    expect(effectiveThreshold(rub(300_000), rub(500_000), "RUB")).toBe(300_000);
    expect(effectiveThreshold(rub(300_000), undefined, "USD")).toBeUndefined();
    expect(effectiveThreshold(rub(300_000), { amount: 1, currency: "USD" }, "RUB")).toBeUndefined();
    expect(parseClientThreshold({ amount: 0, currency: "RUB" })).toEqual(rub(0));
    expect(parseClientThreshold({ amount: Number.MAX_SAFE_INTEGER + 1, currency: "RUB" })).toBeUndefined();
  });
});

describe("дробление по мандату в окне (SPEC §6 п. 9, РП44 п. 1–4, 7; ПС12)", () => {
  const PART = 170_000;
  /** Порог 3 000 ₽ (PARAMS), предел 10 000 ₽, часы Платформы — под рукой теста. */
  function split() {
    let ms = Date.parse("2026-10-19T10:00:00Z");
    const s = setup({ threshold: 300_000, now: () => new Date(ms) });
    s.journal.set(M, { amount_limit: 1_000_000 });
    return { ...s, tick: (sec: number) => (ms += sec * 1000) };
  }
  const op = (op_ref: string, amount = PART, over: Partial<CanonicalMessage> = {}) => msg({ op_ref, amount, ...over });

  it("ПС12: две по 1 700 ₽ — вторая CONFIRMATION_REQUIRED с split_detected: true, без резерва; третья — тоже", async () => {
    const { adp, available } = split();
    expect(pair(await adp.decide(op("a"))).decision).toBe("APPROVE");
    for (const ref of ["b", "c"]) {
      const d = await adp.decide(op(ref));
      expect([pair(d).reason, d.split_detected]).toEqual(["CONFIRMATION_REQUIRED", true]);
    }
    expect(await available()).toBe(1_000_000 - PART);
  });

  it("ПС12: запись в журнал процесса — warn, без реквизитов и без инцидента", async () => {
    const { adp, logs } = split();
    await adp.decide(op("a"));
    await adp.decide(op("b"));
    const rec = logs.find((l) => l.fields.split_detected === true);
    expect(rec?.fields).toEqual({ op_ref: "b", mandate_id: M, window_key: M, ops: 2, sum: 2 * PART, currency: "RUB", split_detected: true });
    expect(JSON.stringify(rec)).not.toMatch(/tok_|token_ref|cryptogram|funding_ref/);
    expect(rec?.fields).not.toHaveProperty("incident");
  });

  it("повтор op_ref доли — тот же ответ со split_detected; с confirmation_ref до PS-19 — тоже (РП44 п. 6)", async () => {
    const { adp } = split();
    await adp.decide(op("a"));
    const first = await adp.decide(op("b"));
    const again = await adp.decide(op("b"));
    expect(again).toEqual({ ...first, decided_in_ms: again.decided_in_ms });
    const c = await adp.decide(op("c", PART, { confirmation_ref: "cnf_1" }));
    expect([pair(c).reason, c.split_detected]).toEqual(["CONFIRMATION_REQUIRED", true]);
  });

  it("граница окна: через 599 с — доля, через 600 с — вне окна, APPROVE", async () => {
    const { adp, tick } = split();
    await adp.decide(op("a"));
    tick(599);
    expect((await adp.decide(op("b"))).split_detected).toBe(true);
    tick(1);
    expect(pair(await adp.decide(op("c"))).decision).toBe("APPROVE");
  });

  it("сумма окна не выше порога — не доля: 1 000 + 1 000 + 1 000 — все APPROVE, четвёртая — доля", async () => {
    const { adp } = split();
    for (const ref of ["a", "b", "c"]) expect(pair(await adp.decide(op(ref, 100_000))).decision).toBe("APPROVE");
    expect((await adp.decide(op("d", 100_000))).split_detected).toBe(true);
  });

  it("операция выше порога — п. 10 (split_detected: false) и в окно не входит", async () => {
    const { adp } = split();
    expect((await adp.decide(op("a", 400_000))).split_detected).toBe(false);
    expect(pair(await adp.decide(op("b"))).decision).toBe("APPROVE");
  });

  it("доля в окно не входит: после доли окно — прежнее", async () => {
    const { adp } = split();
    await adp.decide(op("a"));
    expect((await adp.decide(op("b"))).split_detected).toBe(true);
    expect(pair(await adp.decide(op("c", 100_000))).decision).toBe("APPROVE");
  });

  it("отказ резерва после входа в окно — решение DECLINE убирает запись из окна (РП44 п. 2)", async () => {
    const { adp, broken } = split();
    await adp.decide(op("a"));
    broken.add("reserve");
    expect(await reasonOf(adp, op("b", 100_000))).toBe("STATE_UNAVAILABLE");
    broken.delete("reserve");
    expect(pair(await adp.decide(op("c", 120_000))).decision).toBe("APPROVE");
  });

  it("доля и остаток меньше суммы — LIMIT_EXCEEDED (проверки 7–8 раньше 9), резерва нет", async () => {
    const { adp, journal, available } = split();
    journal.set(M, { amount_limit: 300_000 });
    await adp.decide(op("a"));
    expect(await reasonOf(adp, op("b"))).toBe("LIMIT_EXCEEDED");
    expect(await available()).toBe(300_000 - PART);
  });

  it("ключ окна — корневой INTENT: две CART под одним INTENT — одно окно", async () => {
    const { adp, journal } = split();
    const P = "mnd_00000000-0000-4000-8000-0000000000aa";
    const C2 = "mnd_00000000-0000-4000-8000-0000000000bb";
    journal.set(P, { amount_limit: 1_000_000 });
    journal.set(M, { type: "CART", parent_id: P, amount_limit: 500_000 });
    journal.set(C2, { type: "CART", parent_id: P, amount_limit: 500_000 });
    expect(pair(await adp.decide(op("a"))).decision).toBe("APPROVE");
    const d = await adp.decide(op("b", PART, { aoi: { indicator: true, agent_code: AGENT, mandate_id: C2 } }));
    expect([pair(d).reason, d.split_detected]).toEqual(["CONFIRMATION_REQUIRED", true]);
  });

  it("окна по разным мандатам не смешиваются", async () => {
    const { adp, journal } = split();
    const M2 = "mnd_00000000-0000-4000-8000-0000000000cc";
    journal.set(M2, { amount_limit: 1_000_000 });
    await adp.decide(op("a"));
    expect(pair(await adp.decide(op("b", PART, { aoi: { indicator: true, agent_code: AGENT, mandate_id: M2 } }))).decision).toBe("APPROVE");
  });

  it("окно не прочитано — STATE_UNAVAILABLE без резерва (A3 п. 4.5)", async () => {
    const { adp, broken, available } = split();
    broken.add("enterWindow");
    expect(await reasonOf(adp, op("a"))).toBe("STATE_UNAVAILABLE");
    await expect(available()).rejects.toThrow();
  });

  it("MemoryOperationStore.enterWindow: только у записи «в работе», один раз; разные валюты в окне — исключение", async () => {
    const s = new MemoryOperationStore();
    const rule = { since_ms: 0, threshold: 300_000, min_ops: 2 };
    const e = { key: M, amount: 1, currency: "RUB", at_ms: 1 };
    await expect(s.enterWindow("x", e, rule)).rejects.toThrow();
    await s.begin("x", "h", "t");
    expect(await s.enterWindow("x", e, rule)).toEqual({ entered: true, ops: 1, sum: 1 });
    await expect(s.enterWindow("x", e, rule)).rejects.toThrow();
    await s.begin("y", "h", "t");
    await expect(s.enterWindow("y", { ...e, currency: "USD" }, rule)).rejects.toThrow(/валют/);
  });

  it("MemoryOperationStore.enterWindow: входы старше окна удаляются; сумма вне точного диапазона — исключение (доп. РП44 п. 2)", async () => {
    const s = new MemoryOperationStore();
    const e = { key: M, amount: 100, currency: "RUB", at_ms: 1_000 };
    await s.begin("old", "h", "t");
    await s.enterWindow("old", e, { since_ms: 0, threshold: 300_000, min_ops: 2 });
    await s.begin("new", "h", "t");
    // Вход «old» (1 000 мс) вне окна (since 1 000): не считается и удаляется из перебора.
    expect(await s.enterWindow("new", { ...e, at_ms: 5_000 }, { since_ms: 1_000, threshold: 300_000, min_ops: 2 })).toEqual({
      entered: true,
      ops: 1,
      sum: 100,
    });
    await s.begin("big", "h", "t");
    const huge = { ...e, amount: Number.MAX_SAFE_INTEGER, at_ms: 5_000 };
    await expect(s.enterWindow("big", huge, { since_ms: 1_000, threshold: Number.MAX_SAFE_INTEGER, min_ops: 99 })).rejects.toThrow(
      /точного диапазона/,
    );
  });
});

describe("резерв в П3 и коды П3 → ПИ (SPEC §6 п. 7–8, 11; РП43 п. 3, 5)", () => {
  it("APPROVE: reservation_id = hold.id, agent_level из реестра, mandate_left_after — остаток после резерва", async () => {
    const { adp, ledger, available } = setup();
    const d = await adp.decide(msg());
    expect(pair(d)).toEqual({ decision: "APPROVE", reason: null });
    expect(d.agent_level).toBe(1);
    expect(d.mandate_left_after).toBe(LIMIT - 189_000);
    expect(await available()).toBe(LIMIT - 189_000);
    expect((await ledger.get(d.reservation_id!)).ref).toBe(`mandate:${M}:op:${msg().op_ref}`);
  });

  it("остаток меньше суммы — LIMIT_EXCEEDED (ПС09)", async () => {
    const { adp } = setup();
    expect(await reasonOf(adp, msg({ amount: LIMIT + 1 }))).toBe("LIMIT_EXCEEDED");
  });

  it("сбой хранилища удержаний — STATE_UNAVAILABLE, не BYPASS (РП43 п. 4)", async () => {
    const { adp, broken } = setup();
    broken.add("reserve");
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
  });

  it("STATE_TO_PI — строка на каждый код П3; каждое значение — причина ПИ §6 или INVALID", () => {
    expect(Object.keys(STATE_TO_PI).sort()).toEqual([...STATE_CODES].sort());
    for (const v of Object.values(STATE_TO_PI)) expect(v === "INVALID" || DECISION_REASONS.includes(v)).toBe(true);
    for (const v of Object.values(STATE_TO_PI)) {
      if (v !== "INVALID") expect(() => parseDecision({ decision: "DECLINE", reason: v }, "adp")).not.toThrow();
    }
  });

  it("ПС10 через ADP: 20 одновременных по 100 000 коп. при 300 000 — ровно 3 APPROVE, перерасхода нет", async () => {
    // Сценарий проверяет одно решение — бюджет: правило доли вне залпа (split_min_ops 21 > 20 операций; РП44 доп. п. 1).
    const { adp, available } = setup({ splitMinOps: 21 });
    const ds = await Promise.all(
      Array.from({ length: 20 }, (_, i) => adp.decide(msg({ op_ref: `OPKC-PS10-${i}`, amount: 100_000 }))),
    );
    const kinds = ds.map((d) => pair(d));
    expect(kinds.filter((d) => d.decision === "APPROVE")).toHaveLength(3);
    expect(kinds.filter((d) => d.reason === "LIMIT_EXCEEDED")).toHaveLength(17);
    expect(await available()).toBe(0);
  });

  it("бюджет и дробление в одном залпе (РП44 доп. п. 1): 20 по 100 000 при пределе и пороге 300 000 — ровно 3 APPROVE", async () => {
    const { adp, available, logs } = setup({ threshold: 300_000 });
    const ds = await Promise.all(
      Array.from({ length: 20 }, (_, i) => adp.decide(msg({ op_ref: `OPKC-MIX-${i}`, amount: 100_000 }))),
    );
    // В окно входят первые три по порядку входа (сумма 300 000 не выше порога), все три резервируются — бюджет ровно.
    expect(ds.filter((d) => d.decision === "APPROVE"), "бюджет превышен или недобран (инвариант 4)").toHaveLength(3);
    expect(await available()).toBe(0);
    // Остальные 17 — доли (с ними в окне 4 и больше, сумма выше порога), к резерву не идут. Ответ доли — по остатку,
    // прочитанному без резерва: прочитан до резервов трёх первых — CONFIRMATION_REQUIRED со split_detected: true; после —
    // LIMIT_EXCEEDED (DECLINE, поля split_detected нет — РП44 п. 7). Разбиение 17 между ними зависит от очерёдности.
    const rest = ds.filter((d) => d.decision !== "APPROVE");
    for (const d of rest) {
      if (d.decision === "CONFIRMATION_REQUIRED") expect(d.split_detected).toBe(true);
      else expect([pair(d).reason, d.split_detected]).toEqual(["LIMIT_EXCEEDED", undefined]);
    }
    expect(logs.filter((l) => l.fields.split_detected === true), "каждая из 17 — доля").toHaveLength(17);
  });
});

describe("повтор op_ref (ПИ-1, РП43 п. 5)", () => {
  it("тот же op_ref и сообщение (другой ts) — прежнее решение, одно удержание", async () => {
    const { adp, available } = setup();
    const a = await adp.decide(msg());
    const b = await adp.decide(msg({ ts: "2026-10-19T10:00:05Z" }));
    expect(b.reservation_id).toBe(a.reservation_id);
    expect(pair(b).decision).toBe("APPROVE");
    expect(await available()).toBe(LIMIT - 189_000);
  });

  it("тот же op_ref с другой суммой — STATE_UNAVAILABLE и инцидент, второго резерва нет", async () => {
    const { adp, logs, available } = setup();
    await adp.decide(msg());
    expect(await reasonOf(adp, msg({ amount: 1_000 }))).toBe("STATE_UNAVAILABLE");
    expect(logs.some((l) => l.fields.incident === true)).toBe(true);
    expect(await available()).toBe(LIMIT - 189_000);
  });

  it("повтор APPROVE после освобождения удержания — STATE_UNAVAILABLE, не APPROVE без удержания (инвариант 4)", async () => {
    const { adp, state } = setup();
    const a = await adp.decide(msg());
    await state.release(a.reservation_id!);
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
  });

  it("запись операции потеряна, удержание по ref освобождено — STATE_UNAVAILABLE и запись в журнал (/audit PS-10 № 4)", async () => {
    const { adp, state, journal, logs } = setup();
    const a = await adp.decide(msg());
    await state.release(a.reservation_id!);
    const fresh = new Adp({
      agents: new Agents(),
      mandates: journal,
      state,
      operations: new MemoryOperationStore(),
      params: { aoi_rollout_phase: 3, confirm_above_kop: THRESHOLD, split_window_sec: 600, split_min_ops: 2, client_limit_period_tz: "Europe/Moscow" },
      clientLimits: NO_LIMITS,
      log: (_l, fields, m) => logs.push({ fields, msg: m }),
    });
    expect(await reasonOf(fresh, msg())).toBe("STATE_UNAVAILABLE");
    expect(logs.some((l) => l.fields.incident === true && l.msg.includes("уже освобождено"))).toBe(true);
  });

  it("повтор отказа — прежний отказ", async () => {
    const { adp, agents } = setup();
    agents.map.set(AGENT, "SUSPENDED");
    await adp.decide(msg());
    agents.map.set(AGENT, "ACTIVE");
    expect(await reasonOf(adp, msg())).toBe("AGENT_SUSPENDED");
  });

  it("запись операции не прочитана — STATE_UNAVAILABLE, резерва нет", async () => {
    const { adp, broken, journal } = setup();
    broken.add("begin");
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(journal.calls).toBe(0);
  });

  it("решение не сохранено — APPROVE; повтор видит запись «в работе»: STATE_UNAVAILABLE, удержание не тронуто", async () => {
    const { adp, broken, journal, available, logs } = setup();
    broken.add("finish");
    expect(pair(await adp.decide(msg())).decision).toBe("APPROVE");
    journal.onGet = () => "REVOKED";
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(await available()).toBe(LIMIT - 189_000);
    expect(logs.some((l) => l.msg.includes("не сохранена"))).toBe(true);
  });

  it("одновременные повторы op_ref — один ответ на всех, одно удержание", async () => {
    const { adp, available } = setup();
    const ds = await Promise.all(Array.from({ length: 5 }, () => adp.decide(msg())));
    expect(new Set(ds.map((d) => d.reservation_id)).size).toBe(1);
    expect(ds.every((d) => pair(d).decision === "APPROVE")).toBe(true);
    expect(await available()).toBe(LIMIT - 189_000);
  });

  it("одновременно тот же op_ref с другим продавцом — второй STATE_UNAVAILABLE, не APPROVE на чужое удержание", async () => {
    const { adp, journal } = setup();
    journal.set(M, { merchant_scope: ["MER-1042", "MER-77"] });
    const [a, b] = await Promise.all([adp.decide(msg()), adp.decide(msg({ merchant: { id: "MER-77" } }))]);
    expect(pair(a).decision).toBe("APPROVE");
    expect(pair(b)).toEqual({ decision: "DECLINE", reason: "STATE_UNAVAILABLE" });
  });

  it("запись «в работе» с другого экземпляра — STATE_UNAVAILABLE без резерва", async () => {
    const operations = new MemoryOperationStore();
    await operations.begin(msg().op_ref, "x", "2026-10-19T10:00:00Z");
    const journal = new Journal().set(M);
    const ledger = new AsyncMemoryHoldLedger();
    const adp = new Adp({
      agents: new Agents(),
      mandates: journal,
      state: new StateService(ledger, journal, { reservationTtlSec: 600 }),
      operations,
      params: { aoi_rollout_phase: 3, confirm_above_kop: THRESHOLD, split_window_sec: 600, split_min_ops: 2, client_limit_period_tz: "Europe/Moscow" },
      clientLimits: NO_LIMITS,
    });
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(journal.calls).toBe(0);
  });
});

describe("сверка статуса после резерва (РП43 п. 5, РП41 п. 8, A3 п. 6.3)", () => {
  it("отзыв между проверкой и резервом — MANDATE_REVOKED, удержание освобождено", async () => {
    const { adp, journal, available } = setup();
    journal.onGet = (n) => (n === 2 ? "REVOKED" : undefined);
    expect(await reasonOf(adp, msg())).toBe("MANDATE_REVOKED");
    expect(await available()).toBe(LIMIT);
  });

  it("второе чтение не удалось — STATE_UNAVAILABLE, удержание освобождено", async () => {
    const { adp, journal, available } = setup();
    journal.onGet = (n) => (n === 2 ? "fail" : undefined);
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(await available()).toBe(LIMIT);
  });

  it("освобождение не удалось — отказ остаётся, удержание держит бюджет (безопасная сторона), запись в журнал", async () => {
    const { adp, journal, broken, available, logs } = setup();
    journal.onGet = (n) => (n === 2 ? "REVOKED" : undefined);
    broken.add("release");
    expect(await reasonOf(adp, msg())).toBe("MANDATE_REVOKED");
    expect(await available()).toBe(LIMIT - 189_000);
    expect(logs.some((l) => l.msg.includes("не освобождено"))).toBe(true);
  });
});

describe("П3 на пути ADP — дописывание MANDATE_EXHAUSTED без ожидания (РП43 п. 9)", () => {
  it("reserve с waitExhausted: false отвечает LIMIT_EXCEEDED, не дожидаясь записи журнала", async () => {
    const journal = new Journal().set(M);
    const ledger = new AsyncMemoryHoldLedger();
    let release!: () => void;
    const pending = new Promise<void>((r) => (release = r));
    const state = new StateService(ledger, journal, { reservationTtlSec: 600, exhausted: () => pending });
    const h = await state.reserve(M, { amount: LIMIT, currency: "RUB" }, "op-1");
    expect(h.ok).toBe(true);
    // Закрепление прямо в ядре: запись исчерпания ещё не сделана (сбой после commit, РП41 п. 11).
    if (h.ok) await ledger.commit(h.hold.id, { amount: LIMIT, currency: "RUB" }, true);
    const r = await Promise.race([
      state.reserve(M, { amount: 1, currency: "RUB" }, "op-2", { waitExhausted: false }),
      new Promise((res) => setTimeout(() => res("ждёт"), 200)),
    ]);
    expect(r).toEqual({ ok: false, code: "LIMIT_EXCEEDED" });
    release();
  });
});

describe("признаки уведомителя в записи операции (РП46 доп. п. 7, 9 (о1); A3 п. 5.3)", () => {
  const DAY = { per_period: 300_000, period: "DAY", currency: "RUB" };
  const limits = (rec: unknown): ClientLimitsSource => ({ get: async () => (rec === undefined ? [] : [version(rec)]) });
  const day = (now: Date) => periodStart("DAY", "Europe/Moscow", now);
  const NOW = new Date("2026-10-20T09:00:00Z");
  const ACCOUNT = clientAccountId({ ...CLIENT, period: "DAY", period_start: day(NOW) });

  it("обращений к хранилищу — как в части 2: первое решение периода 11, обычное 8, отказ по лимиту клиента 10", async () => {
    const { adp, io } = setup({ client: limits(DAY), now: () => NOW });
    await adp.decide(msg({ op_ref: "w1", amount: 1_000 }));
    expect(io.n).toBe(11);
    await adp.decide(msg({ op_ref: "w2", amount: 1_000 }));
    expect(io.n).toBe(11 + 8);
    const lim = setup({ client: limits({ ...DAY, per_period: 500 }), now: () => NOW });
    await lim.adp.decide(msg({ op_ref: "d1", amount: 1_000 }));
    expect(lim.io.n).toBe(10);
  });

  it("APPROVE с лимитом клиента — клиент мандата, агент, счёт периода и остаток клиента после резерва", async () => {
    const { adp, records } = setup({ client: limits(DAY), now: () => NOW });
    await adp.decide(msg({ op_ref: "a1", amount: 100_000 }));
    expect(records.get("a1")?.notify).toEqual({ ...CLIENT, agent_code: AGENT, client_account: ACCOUNT, client_left_after: 200_000 });
    await adp.decide(msg({ op_ref: "a2", amount: 200_000 }));
    expect(records.get("a2")?.notify).toMatchObject({ client_account: ACCOUNT, client_left_after: 0 });
  });

  it("APPROVE без записи лимитов — без счёта клиента", async () => {
    const { adp, records } = setup();
    await adp.decide(msg({ op_ref: "a3", amount: 1_000 }));
    expect(records.get("a3")?.notify).toEqual({ ...CLIENT, agent_code: AGENT });
  });

  it("LIMIT_EXCEEDED — чей предел: мандат, per_operation и per_period клиента, подтверждение по меньшему остатку", async () => {
    const mandate = setup();
    await mandate.adp.decide(msg({ op_ref: "m1", amount: LIMIT + 1 }));
    expect(mandate.records.get("m1")?.notify).toEqual({ ...CLIENT, agent_code: AGENT, limit_source: "MANDATE" });
    const perOp = setup({ client: limits({ per_operation: 500, currency: "RUB" }) });
    await perOp.adp.decide(msg({ op_ref: "c1", amount: 1_000 }));
    expect(perOp.records.get("c1")?.notify?.limit_source).toBe("CLIENT");
    const perPeriod = setup({ client: limits({ ...DAY, per_period: 500 }), now: () => NOW });
    await perPeriod.adp.decide(msg({ op_ref: "c2", amount: 1_000 }));
    expect(perPeriod.records.get("c2")?.notify?.limit_source).toBe("CLIENT");
    // Выше порога: остатка мандата хватает, клиента — нет → CLIENT; не хватает мандата → MANDATE.
    const conf = setup({ client: limits({ ...DAY, per_period: 50_000, confirm_above: 10_000 }), now: () => NOW });
    expect(await reasonOf(conf.adp, msg({ op_ref: "c3", amount: 60_000 }))).toBe("LIMIT_EXCEEDED");
    expect(conf.records.get("c3")?.notify?.limit_source).toBe("CLIENT");
    const confM = setup({ client: limits({ ...DAY, per_period: 900_000, confirm_above: 10_000 }), now: () => NOW });
    expect(await reasonOf(confM.adp, msg({ op_ref: "c4", amount: LIMIT + 1 }))).toBe("LIMIT_EXCEEDED");
    expect(confM.records.get("c4")?.notify?.limit_source).toBe("MANDATE");
  });

  it("прочие отказы — без признака источника; до чтения мандата и без клиента — без признаков", async () => {
    const { adp, records, journal, agents } = setup();
    journal.set(M, { status: "REVOKED" });
    await adp.decide(msg({ op_ref: "r1" }));
    expect(records.get("r1")?.notify).toEqual({ ...CLIENT, agent_code: AGENT });
    agents.map.set(AGENT, "SUSPENDED");
    await adp.decide(msg({ op_ref: "r2" }));
    expect(records.get("r2")?.notify).toBeUndefined();
    const orphan = setup();
    orphan.journal.set(M, { client: null });
    await orphan.adp.decide(msg({ op_ref: "r3" }));
    expect(orphan.records.get("r3")?.notify).toBeUndefined();
  });
});

describe("AdpRequestInvalid", () => {
  it("— ошибка с именем поля", () => {
    expect(new AdpRequestInvalid("amount")).toMatchObject({ name: "AdpRequestInvalid", field: "amount" });
  });
});

describe("лимиты клиента в ADP (SPEC §6 п. 6–7, 10–11; РП45 п. 1–2; A3 п. 7.2)", () => {
  const M2 = "mnd_00000000-0000-4000-8000-000000000002";
  /** Хранилище лимитов: запись по клиенту; reads — число чтений; failing — исключение на любое чтение. */
  const limitsOf = (rec: unknown) => {
    const src = {
      reads: 0,
      failing: false,
      rec,
      async get(c: { participant_code: string; principal_ref: string }) {
        src.reads++;
        if (src.failing) throw new Error("хранилище лимитов недоступно");
        const own = c.participant_code === CLIENT.participant_code && c.principal_ref === CLIENT.principal_ref;
        return own && src.rec !== undefined ? [version(src.rec)] : [];
      },
    };
    return src;
  };
  const DAY = { per_period: 300_000, period: "DAY", currency: "RUB" };

  it("страж инварианта 2: хранилище лимитов бросает на любое чтение — неагентская всё равно BYPASS, чтений нет", async () => {
    const src = limitsOf(DAY);
    src.failing = true;
    const { adp } = setup({ client: src });
    expect(pair(await adp.decide(plain()))).toEqual({ decision: "BYPASS", reason: null });
    expect(pair(await adp.decide(msg({ aoi: null as unknown as undefined })))).toEqual({ decision: "BYPASS", reason: null });
    expect(src.reads).toBe(0);
    // Агентская при том же сбое — не BYPASS и не APPROVE: не подтверждено (A3 п. 4.5).
    expect(await reasonOf(adp, msg())).toBe("STATE_UNAVAILABLE");
  });

  it("одно чтение лимитов на решение: MCC, per_operation, порог и per_period — из одной записи", async () => {
    const src = limitsOf({ ...DAY, per_operation: 200_000, confirm_above: 250_000, merchant_categories: ["5462"] });
    const { adp } = setup({ client: src });
    expect(pair(await adp.decide(msg())).decision).toBe("APPROVE");
    expect(src.reads).toBe(1);
  });

  it("per_operation: сумма выше — LIMIT_EXCEEDED до резерва; равна — APPROVE", async () => {
    const { adp, available } = setup({ client: limitsOf({ per_operation: 189_000 - 1, currency: "RUB" }) });
    expect(await reasonOf(adp, msg())).toBe("LIMIT_EXCEEDED");
    await expect(available()).rejects.toThrow();
    const ok = setup({ client: limitsOf({ per_operation: 189_000, currency: "RUB" }) });
    expect(pair(await ok.adp.decide(msg())).decision).toBe("APPROVE");
  });

  it("merchant_categories: MCC вне списка или без MCC — MANDATE_SCOPE до резерва; в списке — APPROVE", async () => {
    const { adp, available } = setup({ client: limitsOf({ merchant_categories: ["5411"] }) });
    expect(await reasonOf(adp, msg())).toBe("MANDATE_SCOPE");
    expect(await reasonOf(adp, msg({ op_ref: "no-mcc", merchant: { id: "MER-1042" } }))).toBe("MANDATE_SCOPE");
    await expect(available()).rejects.toThrow();
    expect(pair(await setup({ client: limitsOf({ merchant_categories: ["5411", "5462"] }) }).adp.decide(msg())).decision).toBe("APPROVE");
  });

  it("per_period — второй счёт тем же op_ref по всем мандатам клиента; отказ — резерв мандата освобождён", async () => {
    const { adp, journal, ledger, available } = setup({ client: limitsOf({ ...DAY, per_period: 300_000 }) });
    journal.set(M2);
    const d1 = await adp.decide(msg({ op_ref: "p1", amount: 200_000 }));
    expect(pair(d1).decision).toBe("APPROVE");
    // reservation_id — удержание мандата; удержание клиента — в записи операции следом.
    expect((await ledger.get(d1.reservation_id!)).account).toBe(accountId(M));
    const d2 = await adp.decide(msg({ op_ref: "p2", amount: 200_000, aoi: { indicator: true, agent_code: AGENT, mandate_id: M2 } }));
    expect(pair(d2).reason).toBe("LIMIT_EXCEEDED");
    expect(await available(M2)).toBe(LIMIT);
    const d3 = await adp.decide(msg({ op_ref: "p3", amount: 100_000, aoi: { indicator: true, agent_code: AGENT, mandate_id: M2 } }));
    expect(pair(d3).decision).toBe("APPROVE");
    expect(d3.mandate_left_after).toBe(0);
  });

  it("повтор op_ref по освобождённому удержанию клиента — STATE_UNAVAILABLE, не прежний APPROVE (инвариант 4)", async () => {
    const { adp, ledger } = setup({ client: limitsOf(DAY) });
    const m = msg({ op_ref: "rep", amount: 1_000 });
    expect(pair(await adp.decide(m)).decision).toBe("APPROVE");
    const clientHold = (await ledger.expire(Number.MAX_SAFE_INTEGER)).find((h) => h.account.startsWith("client:"));
    expect(clientHold).toBeDefined();
    expect(await reasonOf(adp, m)).toBe("STATE_UNAVAILABLE");
  });

  it("подтверждение без резерва — остаток с учётом лимита клиента: выше порога и выше остатка клиента — LIMIT_EXCEEDED", async () => {
    const { adp } = setup({ client: limitsOf({ ...DAY, per_period: 50_000, confirm_above: 10_000 }) });
    expect(await reasonOf(adp, msg({ amount: 60_000 }))).toBe("LIMIT_EXCEEDED");
    expect(await reasonOf(adp, msg({ op_ref: "c2", amount: 40_000 }))).toBe("CONFIRMATION_REQUIRED");
  });

  it("записи нет — только предел мандата; не прочитана, мандат без клиента, валюта ≠ операции — STATE_UNAVAILABLE", async () => {
    expect(pair(await setup({ client: limitsOf(undefined) }).adp.decide(msg())).decision).toBe("APPROVE");
    const down = limitsOf(DAY);
    down.failing = true;
    expect(await reasonOf(setup({ client: down }).adp, msg())).toBe("STATE_UNAVAILABLE");
    const orphan = setup({ client: limitsOf(DAY) });
    orphan.journal.set(M, { client: null });
    expect(await reasonOf(orphan.adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(await reasonOf(setup({ client: limitsOf({ ...DAY, currency: "USD" }) }).adp, msg())).toBe("STATE_UNAVAILABLE");
  });
});

describe("лимит за период: снятие или смена вида — со следующего периода (РП45 п. 1, /audit № 1)", () => {
  /** История версий клиента CLIENT; часы ADP — подвижные. */
  const history = (...vs: { limits: unknown; received_at: string }[]): ClientLimitsSource => ({ get: async () => vs });
  const DAY2 = { per_period: 200_000, period: "DAY", currency: "RUB" };
  const MONTH2 = { per_period: 200_000, period: "MONTH", currency: "RUB" };
  const withMandate2 = (j: { set: (id: string, over?: object) => unknown }) => j.set("mnd_00000000-0000-4000-8000-000000000009");
  const on = (op_ref: string, mandate_id = M) => msg({ op_ref, amount: 150_000, aoi: { indicator: true, agent_code: AGENT, mandate_id } });

  it("обход (а): новая версия без per_period — до конца суток прежний дневной лимит, с 00:00 МСК — снят", async () => {
    let now = Date.parse("2026-10-19T12:00:00Z");
    const src = history(version(DAY2, "2026-10-01T00:00:00Z"), version({ per_operation: 500_000, currency: "RUB" }, "2026-10-19T11:00:00Z"));
    const { adp, journal } = setup({ client: src, now: () => new Date(now) });
    withMandate2(journal);
    expect(pair(await adp.decide(on("a1"))).decision).toBe("APPROVE");
    expect(await reasonOf(adp, on("a2", "mnd_00000000-0000-4000-8000-000000000009"))).toBe("LIMIT_EXCEEDED");
    now = Date.parse("2026-10-19T21:00:00Z"); // 00:00 МСК 20.10
    expect(pair(await adp.decide(on("a3", "mnd_00000000-0000-4000-8000-000000000009"))).decision).toBe("APPROVE");
  });

  it("обход (б): MONTH израсходован → DAY с полным пределом — до конца месяца действует месячный", async () => {
    // Расход по месячному — 10.10, смена на DAY — 19.10: дневной счёт 19.10 пуст, обход дал бы полный дневной предел.
    let now = Date.parse("2026-10-10T12:00:00Z");
    const src = history(version(MONTH2, "2026-09-01T00:00:00Z"), version(DAY2, "2026-10-19T13:00:00Z"));
    const { adp, journal } = setup({ client: src, now: () => new Date(now) });
    withMandate2(journal);
    expect(pair(await adp.decide(on("b1"))).decision).toBe("APPROVE"); // 150 000 из месячных 200 000
    now = Date.parse("2026-10-19T14:00:00Z"); // после смены на DAY
    expect(await reasonOf(adp, on("b2", "mnd_00000000-0000-4000-8000-000000000009"))).toBe("LIMIT_EXCEEDED");
    now = Date.parse("2026-10-31T21:00:00Z"); // 00:00 МСК 01.11 — дневной
    expect(pair(await adp.decide(on("b3", "mnd_00000000-0000-4000-8000-000000000009"))).decision).toBe("APPROVE");
  });

  it("история не по форме (не массив, версия без received_at) — STATE_UNAVAILABLE", async () => {
    expect(await reasonOf(setup({ client: { get: async () => ({ limits: DAY2 }) } }).adp, msg())).toBe("STATE_UNAVAILABLE");
    expect(await reasonOf(setup({ client: { get: async () => [{ limits: DAY2 }] } }).adp, msg())).toBe("STATE_UNAVAILABLE");
  });
});

describe("порт лимитов клиента обязателен (решение владельца по /audit, РП45)", () => {
  it("без clientLimits ADP не собирается — ошибка типов (npm run check в CI), а не «проверки нет»", () => {
    const base = {
      agents: new Agents(),
      mandates: new Journal(),
      state: new StateService(new AsyncMemoryHoldLedger(), new Journal(), { reservationTtlSec: 600 }),
      operations: new MemoryOperationStore(),
      params: { aoi_rollout_phase: 3 as const, confirm_above_kop: THRESHOLD, split_window_sec: 600, split_min_ops: 2, client_limit_period_tz: "Europe/Moscow" },
    };
    // @ts-expect-error — clientLimits обязателен: станет необязательным — эта строка сломает npm run check.
    const make = () => new Adp(base);
    expect(typeof make).toBe("function");
    expect(new Adp({ ...base, clientLimits: NO_LIMITS })).toBeInstanceOf(Adp);
  });
});

describe("лимит клиента: CART, отзыв после резерва, сужение и расширение через ADP (РП45 п. 1, РП46 (г); /audit № 4)", () => {
  const C = "mnd_00000000-0000-4000-8000-0000000000c1";
  const NOW = new Date("2026-10-19T10:00:00Z");
  const DAY = (per_period: number) => ({ per_period, period: "DAY", currency: "RUB" });
  const clientAcc = clientAccountId({ ...CLIENT, period: "DAY", period_start: periodStart("DAY", "Europe/Moscow", NOW) });
  /** Подвижная история версий клиента CLIENT. */
  const mutable = (...vs: { limits: unknown; received_at: string }[]) => {
    const src = { vs, get: async () => src.vs };
    return src;
  };

  it("CART: порядок CART → родитель → клиент; отказ клиента освобождает оба удержания мандатов", async () => {
    const { adp, journal, ledger, available } = setup({ client: mutable(version(DAY(100_000))), now: () => NOW });
    journal.set(C, { type: "CART", parent_id: M, amount_limit: 200_000 });
    const d = await adp.decide(msg({ op_ref: "cart-1", amount: 150_000, aoi: { indicator: true, agent_code: AGENT, mandate_id: C } }));
    expect(pair(d).reason).toBe("LIMIT_EXCEEDED");
    expect(await available(C)).toBe(200_000);
    expect(await available(M)).toBe(LIMIT);
    // Под лимитом — три удержания по порядку: CART, родитель, клиент.
    const ok = await adp.decide(msg({ op_ref: "cart-2", amount: 50_000, aoi: { indicator: true, agent_code: AGENT, mandate_id: C } }));
    expect(pair(ok).decision).toBe("APPROVE");
    expect((await ledger.get(ok.reservation_id!)).account).toBe(accountId(C));
    expect((await ledger.available(clientAcc)).amount).toBe(50_000);
  });

  it("отзыв после резерва (п. 12) освобождает и удержание клиента", async () => {
    const { adp, journal, ledger, available } = setup({ client: mutable(version(DAY(300_000))), now: () => NOW });
    journal.onGet = (n) => (n === 2 ? "REVOKED" : undefined);
    expect(await reasonOf(adp, msg({ op_ref: "rev-1", amount: 100_000 }))).toBe("MANDATE_REVOKED");
    expect(await available()).toBe(LIMIT);
    expect((await ledger.available(clientAcc)).amount).toBe(300_000);
  });

  it("сужение per_period в периоде через ADP — сразу (setLimit, РП46 (г)): под новым пределом — APPROVE, сверх — LIMIT_EXCEEDED", async () => {
    const src = mutable(version(DAY(300_000)));
    const { adp, journal, ledger, available } = setup({ client: src, now: () => NOW });
    journal.set("mnd_00000000-0000-4000-8000-0000000000c2");
    expect(pair(await adp.decide(msg({ op_ref: "nar-1", amount: 50_000 }))).decision).toBe("APPROVE");
    src.vs = [...src.vs, version(DAY(100_000), "2026-10-19T09:30:00Z")];
    const m2 = "mnd_00000000-0000-4000-8000-0000000000c2";
    const aoi = { indicator: true, agent_code: AGENT, mandate_id: m2 };
    expect(await reasonOf(adp, msg({ op_ref: "nar-2", amount: 60_000, aoi }))).toBe("LIMIT_EXCEEDED");
    expect(await available(m2)).toBe(LIMIT);
    expect(pair(await adp.decide(msg({ op_ref: "nar-3", amount: 50_000, aoi }))).decision).toBe("APPROVE");
    expect(await ledger.account(clientAcc)).toMatchObject({ limit: 100_000, reserved: 100_000 });
  });

  it("расширение per_period в периоде через ADP — сразу (РП46 (г), снимает остаточный риск 2 РП45)", async () => {
    const src = mutable(version(DAY(100_000)));
    const { adp, ledger } = setup({ client: src, now: () => NOW });
    expect(pair(await adp.decide(msg({ op_ref: "wid-1", amount: 100_000 }))).decision).toBe("APPROVE");
    src.vs = [...src.vs, version(DAY(250_000), "2026-10-19T09:30:00Z")];
    expect(pair(await adp.decide(msg({ op_ref: "wid-2", amount: 150_000 }))).decision).toBe("APPROVE");
    expect(await ledger.account(clientAcc)).toMatchObject({ limit: 250_000, reserved: 250_000 });
  });

  it.todo(
    "PS-16 (обязательное условие, /audit № 2): клиринг закрепляет и освобождает оба удержания — мандата и клиента — по записи операции (op_ref → holds); закреплённое удержание клиента проход expire не освобождает, per_period не превышается после клиринга",
  );
});
