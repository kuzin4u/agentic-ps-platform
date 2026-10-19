// П4 точка решения ADP (PS-10, РП43) на удержаниях ядра в памяти: BYPASS первой проверкой до ввода-вывода (инвариант 2),
// порядок проверок SPEC §6, коды П3 → ПИ (п. 3), неподтверждённое состояние — отказ (п. 4, A3 п. 4.5), резерв по op_ref и
// повтор (п. 5), сверка статуса после резерва (п. 5, РП41 п. 8). Каждое решение — согласованная пара (parseDecision, РП19).
import { AsyncMemoryHoldLedger, type AsyncHoldLedger } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import {
  Adp,
  AdpRequestInvalid,
  isBypass,
  MemoryOperationStore,
  STATE_TO_PI,
  STATUS_TO_PI,
  type AdpAgents,
  type AdpMandate,
  type AdpMandates,
} from "../../src/adp/index.js";
import type { MandateStatus } from "../../src/consent/model.js";
import type { AgentStatus } from "../../src/registry/model.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { DECISION_REASONS, parseDecision } from "../../src/shared/codes.js";
import { accountId, STATE_CODES, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";

const AGENT = "nspk:agent:buyref-01:v3";
const OTHER = "nspk:agent:other-02:v1";
const M = "mnd_00000000-0000-4000-8000-000000000001";
const LIMIT = 300_000;
const THRESHOLD = 1_000_000;

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
  #n = 0;
  set(id: string, over: Partial<Row> = {}): this {
    this.map.set(id, {
      agent_code: AGENT,
      status: "ACTIVE",
      type: "INTENT",
      merchant_scope: ["MER-1042"],
      currency: "RUB",
      amount_limit: LIMIT,
      ...over,
    });
    return this;
  }
  async get(id: string, agent_code: string): Promise<AdpMandate | undefined> {
    this.calls++;
    if (this.failing) throw new Error("журнал недоступен");
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

function setup(opts: { phase?: 1 | 2 | 3 } = {}) {
  const agents = new Agents();
  const journal = new Journal().set(M);
  const ledger = new AsyncMemoryHoldLedger();
  const broken = new Set<string>();
  const io = { n: 0 };
  const state = new StateService(spy<AsyncHoldLedger>(ledger, broken, io), journal, { reservationTtlSec: 600 });
  const operations = spy(new MemoryOperationStore(), broken, io);
  const logs: { fields: Record<string, unknown>; msg: string }[] = [];
  const adp = new Adp({
    agents,
    mandates: journal,
    state,
    operations,
    params: { aoi_rollout_phase: opts.phase ?? 3, confirm_above_kop: THRESHOLD },
    log: (_l, fields, m) => logs.push({ fields, msg: m }),
  });
  const available = async (id = M) => (await ledger.available(accountId(id))).amount;
  return { adp, agents, journal, ledger, state, broken, io, logs, available };
}

/** Решение ADP — только согласованная пара (РП19); иначе parseDecision бросает. */
const pair = (d: Decision) => parseDecision(d, "adp");
const reasonOf = async (adp: Adp, m: CanonicalMessage) => pair(await adp.decide(m)).reason;

describe("BYPASS — первая проверка (РП4, РП43 п. 1, инвариант 2)", () => {
  it("нет aoi и CARD_TOKEN — BYPASS / null при сбое реестра, журнала, П3 и записи операций, без обращений к ним", async () => {
    const { adp, agents, journal, broken, io } = setup();
    agents.failing = true;
    journal.failing = true;
    for (const m of ["begin", "finish", "get", "reserve", "available", "release", "account"]) broken.add(m);
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

  it("сумма выше confirm_above_kop до PS-13 — CONFIRMATION_REQUIRED / CONFIRMATION_REQUIRED, с confirmation_ref — то же", async () => {
    const { adp, journal } = setup();
    journal.set(M, { amount_limit: 2 * THRESHOLD });
    expect(pair(await adp.decide(msg({ op_ref: "a", amount: THRESHOLD + 1 })))).toEqual({
      decision: "CONFIRMATION_REQUIRED",
      reason: "CONFIRMATION_REQUIRED",
    });
    expect(await reasonOf(adp, msg({ op_ref: "b", amount: THRESHOLD + 1, confirmation_ref: "cnf_1" }))).toBe(
      "CONFIRMATION_REQUIRED",
    );
  });

  it("сумма выше порога и выше остатка — LIMIT_EXCEEDED (проверки 7–8 раньше 9–10), резерва нет", async () => {
    const { adp, available } = setup();
    expect(await reasonOf(adp, msg({ amount: THRESHOLD + 1 }))).toBe("LIMIT_EXCEEDED");
    await expect(available()).rejects.toThrow();
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
    const { adp, available } = setup();
    const ds = await Promise.all(
      Array.from({ length: 20 }, (_, i) => adp.decide(msg({ op_ref: `OPKC-PS10-${i}`, amount: 100_000 }))),
    );
    const kinds = ds.map((d) => pair(d));
    expect(kinds.filter((d) => d.decision === "APPROVE")).toHaveLength(3);
    expect(kinds.filter((d) => d.reason === "LIMIT_EXCEEDED")).toHaveLength(17);
    expect(await available()).toBe(0);
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
      params: { aoi_rollout_phase: 3, confirm_above_kop: THRESHOLD },
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

describe("AdpRequestInvalid", () => {
  it("— ошибка с именем поля", () => {
    expect(new AdpRequestInvalid("amount")).toMatchObject({ name: "AdpRequestInvalid", field: "amount" });
  });
});
