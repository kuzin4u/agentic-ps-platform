// П6 в ADP (PS-19 ч. 1, РП50 п. 1–3, 7–10; SPEC §6 п. 9–10; A7 п. 7; инвариант 7): запрос подтверждения на
// CONFIRMATION_REQUIRED с итоговыми значениями из сообщения процессинга, проверка confirmation_ref до порога и окна,
// погашение после резерва. Решение человека здесь пишется хранилищем напрямую (approve) — **не доказательство ПИ-8**:
// путь через банк (подпись, totals_hash, срок) — participants-confirm.test.ts и ПС11 на стенде.
// Реквизит — помощник agentToken (однократность криптограммы — не предмет этих тестов).
import { AsyncMemoryHoldLedger } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import { Adp, MemoryOperationStore, type AdpCredentials, type AdpMandate, type AdpMandates } from "../../src/adp/index.js";
import {
  CONFIRMATION_REF,
  MemoryConfirmationStore,
  newConfirmationId,
  newConfirmationRef,
  totalsHash,
  type ConfirmationRecord,
  type ConfirmationStore,
} from "../../src/confirm/index.js";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { accountId, StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";
import { agentToken, agentTokenCredentials } from "../support/agent-token.js";

const AGENT = "nspk:agent:buyref-01:v3";
const ROOT = "mnd_00000000-0000-4000-8000-0000000000f0";
const M = "mnd_00000000-0000-4000-8000-000000000001";
/** Порог 3 000 ₽ (ПС11), предел CART 10 000 ₽, корня — больше. */
const THRESHOLD = 300_000;
const LIMIT = 1_000_000;
const HOLD_SEC = 900;
const T0 = Date.parse("2026-10-22T10:00:00.000Z");
const CLIENT = { participant_code: "bank:a", principal_ref: "prn_7f3c9a" } as const;

class Journal implements AdpMandates, MandateBudgetSource {
  /** Номер чтения ADP, на котором мандат читается отозванным: у CART 1 — M (п. 5), 2 — корень, 3 — M (сверка п. 12). */
  #revokeAt?: number;
  #reads = 0;
  /** Отзыв на n-м чтении следующей авторизации (отсчёт — с этого вызова). */
  revokeAtRead(n: number): void {
    this.#reads = 0;
    this.#revokeAt = n;
  }
  readonly map = new Map<string, AdpMandate>([
    [ROOT, { status: "ACTIVE", type: "INTENT", merchant_scope: ["MER-1042", "MER-2210"], currency: "RUB", amount_limit: 100 * LIMIT, client: CLIENT }],
    [M, { status: "ACTIVE", type: "CART", parent_id: ROOT, merchant_scope: ["MER-1042", "MER-2210"], currency: "RUB", amount_limit: LIMIT, client: CLIENT }],
  ]);
  async get(id: string, agent_code: string): Promise<AdpMandate | undefined> {
    if (agent_code !== AGENT) return undefined;
    const m = this.map.get(id);
    return m && ++this.#reads === this.#revokeAt ? { ...m, status: "REVOKED" } : m;
  }
  async budget(id: string): Promise<MandateBudget | undefined> {
    const m = this.map.get(id);
    return m && { status: m.status ?? "ACTIVE", amount_limit: m.amount_limit, currency: m.currency };
  }
}

/** Хранилище П6 с отказом и подменой по выбору и счётчиком обращений. */
function wrap(inner: ConfirmationStore, broken: Set<string>, calls: string[], over: Partial<ConfirmationStore> = {}): ConfirmationStore {
  return new Proxy(inner, {
    get(t, p, r) {
      const v = (over as Record<string | symbol, unknown>)[p] ?? (Reflect.get(t, p, r) as unknown);
      if (typeof v !== "function") return v;
      return (...a: unknown[]) => {
        calls.push(String(p));
        if (broken.has(String(p))) return Promise.reject(new Error("ECONNRESET"));
        return (v as (...x: unknown[]) => unknown).apply(t, a);
      };
    },
  });
}

let opSeq = 0;
const op = () => `OPKC-20261022-${String(++opSeq).padStart(6, "0")}`;

const auth = (over: Partial<CanonicalMessage> = {}): CanonicalMessage =>
  agentToken({
    op_ref: op(),
    msg_type: "AUTH_REQUEST",
    channel: "CARD",
    amount: 340_000,
    currency: "RUB",
    merchant: { id: "MER-1042", mcc: "5462" },
    instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
    aoi: { indicator: true, agent_code: AGENT, mandate_id: M },
    order_ref: "ORD-77a1",
    ...over,
  });

function setup(
  opts: { splitMinOps?: number; over?: Partial<ConfirmationStore>; connected?: boolean; credentials?: AdpCredentials } = {},
) {
  let t = T0;
  const now = () => new Date(t);
  const journal = new Journal();
  const ledger = new AsyncMemoryHoldLedger();
  const state = new StateService(ledger, journal, { reservationTtlSec: 600, now });
  const inner = new MemoryConfirmationStore();
  const broken = new Set<string>();
  const calls: string[] = [];
  const store = wrap(inner, broken, calls, opts.over);
  const logs: { fields: Record<string, unknown>; msg: string }[] = [];
  const adp = new Adp({
    agents: { get: (c) => (c === AGENT ? { status: "ACTIVE", level: 1 } : undefined) },
    mandates: journal,
    state,
    operations: new MemoryOperationStore(),
    credentials: opts.credentials ?? agentTokenCredentials,
    ...(opts.connected === false ? {} : { confirmations: { store, order_hold_sec: HOLD_SEC } }),
    params: {
      aoi_rollout_phase: 3,
      confirm_above_kop: THRESHOLD,
      split_window_sec: 600,
      split_min_ops: opts.splitMinOps ?? 21,
      client_limit_period_tz: "Europe/Moscow",
    },
    clientLimits: { get: async () => [] },
    now,
    log: (_l, fields, m) => logs.push({ fields, msg: m }),
  });
  /** Запросы П6 по ключу заказа сообщения. */
  const requests = (m: CanonicalMessage) =>
    inner.byKey({ mandate_id: M, merchant_id: m.merchant.id as string, order_ref: m.order_ref as string, amount: m.amount, currency: m.currency });
  /** Решение человека — записью хранилища, не через ПИ-8 (см. шапку). */
  const approve = async (r: ConfirmationRecord, decision: "APPROVE" | "REJECT" = "APPROVE"): Promise<string> => {
    const ref = newConfirmationRef();
    const d = { participant_code: CLIENT.participant_code, kid: "kid-test", decision, totals_hash: totalsHash(r), decided_at: now().toISOString(), signature: "x".repeat(86) };
    const done = await inner.decide(r.confirmation_id, d, decision === "APPROVE" ? ref : null, now().toISOString());
    expect(done?.status, "решение в хранилище не записано").toBe(decision === "APPROVE" ? "APPROVED" : "REJECTED");
    return ref;
  };
  /** Счёт открывается первым резервом: до него весь предел свободен. */
  const available = async (id = M) => {
    try {
      return (await ledger.available(accountId(id))).amount;
    } catch (err) {
      if ((err as Error).message === "UNKNOWN_ACCOUNT") return journal.map.get(id)!.amount_limit;
      throw err;
    }
  };
  return { adp, journal, inner, broken, calls, logs, requests, approve, available, advance: (ms: number) => (t += ms), now };
}

/** Согласованная пара (РП19) и split_detected решения — его pair не возвращает. */
const pair = (d: Decision) => ({ ...parseDecision(d, "adp"), ...(d.split_detected === undefined ? {} : { split_detected: d.split_detected }) });
const incidents = (logs: { fields: Record<string, unknown> }[]) => logs.filter((l) => l.fields.incident === true);

describe("ПС11 в ADP: подтверждение выше порога и повтор с confirmation_ref (РП50; не доказательство ПИ-8)", () => {
  it("3 400 ₽ > 3 000 ₽ → CONFIRMATION_REQUIRED и запрос на итоговые значения сообщения; срок — order_hold_sec", async () => {
    const s = setup();
    const m = auth();
    const d = pair(await s.adp.decide(m));
    expect(d).toMatchObject({ decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED", split_detected: false });
    const [r, ...rest] = await s.requests(m);
    expect(rest, "на один заказ — один запрос").toEqual([]);
    expect(r).toMatchObject({
      agent_code: AGENT,
      mandate_id: M,
      merchant_id: "MER-1042",
      amount: 340_000,
      currency: "RUB",
      order_ref: "ORD-77a1",
      split_detected: false,
      status: "PENDING",
      confirmation_ref: null,
      created_at: new Date(T0).toISOString(),
      expires_at: new Date(T0 + HOLD_SEC * 1000).toISOString(),
    });
    expect(await s.available(), "без подтверждения резерва нет").toBe(LIMIT);
  });

  it("доказательный: одобрение человеком → повтор с confirmation_ref — APPROVE с резервом, ссылка USED с op_ref", async () => {
    const s = setup();
    const first = auth();
    expect(pair(await s.adp.decide(first)).decision).toBe("CONFIRMATION_REQUIRED");
    const [r] = await s.requests(first);
    const ref = await s.approve(r!);
    expect(ref).toMatch(CONFIRMATION_REF);
    const retry = auth({ confirmation_ref: ref });
    expect(pair(await s.adp.decide(retry))).toMatchObject({ decision: "APPROVE", reason: null });
    expect(await s.available(), "резерв на сумму операции (инвариант 4)").toBe(LIMIT - 340_000);
    const used = await s.inner.byRef(ref);
    expect(used).toMatchObject({ status: "USED", op_ref: retry.op_ref });
  });

  it("повторное CONFIRMATION_REQUIRED на тот же заказ до решения — тот же запрос, нового нет", async () => {
    const s = setup();
    await s.adp.decide(auth());
    s.advance(60_000);
    expect(pair(await s.adp.decide(auth())).decision).toBe("CONFIRMATION_REQUIRED");
    expect(await s.requests(auth())).toHaveLength(1);
  });

  it("другая сумма того же заказа — другой ключ и свой запрос", async () => {
    const s = setup();
    await s.adp.decide(auth());
    await s.adp.decide(auth({ amount: 350_000 }));
    expect(await s.requests(auth())).toHaveLength(1);
    expect(await s.requests(auth({ amount: 350_000 }))).toHaveLength(1);
  });

  it("ревью № 1: после USED тот же заказ с новым op_ref — CONFIRMATION_REQUIRED, запросов в П6 не прибавилось", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const ref = await s.approve(r!);
    expect(pair(await s.adp.decide(auth({ confirmation_ref: ref }))).decision).toBe("APPROVE");
    for (const again of [auth({ confirmation_ref: ref }), auth()]) {
      expect(pair(await s.adp.decide(again)).decision, "повтор по прежнему подтверждению недопустим (A7 п. 7.3)").toBe("CONFIRMATION_REQUIRED");
    }
    const all = await s.requests(auth());
    expect(all.map((x) => x.status)).toEqual(["USED"]);
    // Использованная ссылка отсекается проверкой до резерва (РП50 п. 7), а не только условием погашения (ворота К1 № 1).
    expect(s.calls.filter((c) => c === "consume"), "погашение по использованной ссылке").toHaveLength(1);
    expect(await s.available(), "второго резерва нет").toBe(LIMIT - 340_000);
  });

  it("после REJECTED и после EXPIRED нового запроса на тот же заказ нет (РП50 п. 9)", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    await s.approve(r!, "REJECT");
    expect(pair(await s.adp.decide(auth())).decision).toBe("CONFIRMATION_REQUIRED");
    expect((await s.requests(auth())).map((x) => x.status)).toEqual(["REJECTED"]);

    const order = { order_ref: "ORD-77a2" };
    await s.adp.decide(auth(order));
    s.advance(HOLD_SEC * 1000);
    expect(pair(await s.adp.decide(auth(order))).decision).toBe("CONFIRMATION_REQUIRED");
    expect((await s.requests(auth(order))).map((x) => x.status), "PENDING после срока переводится в EXPIRED при обращении").toEqual(["EXPIRED"]);
  });

  it("одобренная ссылка после срока не действует: CONFIRMATION_REQUIRED, ссылка не погашена, резерва нет", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const ref = await s.approve(r!);
    s.advance(HOLD_SEC * 1000);
    expect(pair(await s.adp.decide(auth({ confirmation_ref: ref }))).decision).toBe("CONFIRMATION_REQUIRED");
    expect((await s.inner.byRef(ref))?.status).toBe("APPROVED");
    expect(await s.available()).toBe(LIMIT);
    expect(s.calls, "срок проверяется до резерва, а не только условием погашения").not.toContain("consume");
  });

  it("ссылка на другие итоговые значения (сумма, продавец, order_ref) — не учитывается, инцидент, ссылка не погашена", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const ref = await s.approve(r!);
    // Валюты здесь нет: другая валюта отсекается п. 6 (валюта мандата) раньше сверки ссылки — сравнение currency в
    // sameTotals страхующее (ворота К1 № 12).
    const others: Partial<CanonicalMessage>[] = [
      { amount: 339_000 },
      { merchant: { id: "MER-2210", mcc: "5462" } },
      { order_ref: "ORD-other" },
    ];
    for (const over of others) {
      const before = incidents(s.logs).length;
      const d = pair(await s.adp.decide(auth({ ...over, confirmation_ref: ref })));
      expect(d.decision, JSON.stringify(over)).toBe("CONFIRMATION_REQUIRED");
      expect(incidents(s.logs).length, `инцидент подмены итога: ${JSON.stringify(over)}`).toBe(before + 1);
    }
    expect(JSON.stringify(incidents(s.logs)), "значение ссылки в журнал процесса не попадает").not.toContain(ref);
    expect((await s.inner.byRef(ref))?.status).toBe("APPROVED");
    expect(await s.available()).toBe(LIMIT);
  });

  it("ссылка другого агента на тот же мандат и заказ — не учитывается, инцидент", async () => {
    const s = setup();
    const m = auth();
    const r: ConfirmationRecord = {
      confirmation_id: newConfirmationId(),
      agent_code: "nspk:agent:other-02:v1",
      mandate_id: M,
      merchant_id: "MER-1042",
      amount: 340_000,
      currency: "RUB",
      order_ref: "ORD-77a1",
      split_detected: false,
      status: "PENDING",
      created_at: new Date(T0).toISOString(),
      expires_at: new Date(T0 + HOLD_SEC * 1000).toISOString(),
      confirmation_ref: null,
      decision: null,
      op_ref: null,
    };
    await s.inner.create(r);
    const ref = await s.approve(r);
    expect(pair(await s.adp.decide({ ...m, confirmation_ref: ref })).decision).toBe("CONFIRMATION_REQUIRED");
    expect(incidents(s.logs)).toHaveLength(1);
  });

  it("неизвестная ссылка и ссылка не по форме — не учитываются: CONFIRMATION_REQUIRED, без инцидента", async () => {
    const s = setup();
    for (const ref of [newConfirmationRef(), "cnf_not-a-ref", "x".repeat(40)]) {
      expect(pair(await s.adp.decide(auth({ confirmation_ref: ref }))).decision).toBe("CONFIRMATION_REQUIRED");
    }
    expect(incidents(s.logs)).toEqual([]);
  });

  it("без order_ref — CONFIRMATION_REQUIRED без запроса (привязать нечего)", async () => {
    const s = setup();
    const m = auth();
    delete m.order_ref;
    expect(pair(await s.adp.decide(m)).decision).toBe("CONFIRMATION_REQUIRED");
    expect(s.calls.filter((c) => c === "create")).toEqual([]);
  });

  it("повтор op_ref одобренной по ссылке операции — прежнее решение, второго погашения нет", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const retry = auth({ confirmation_ref: await s.approve(r!) });
    const d1 = await s.adp.decide(retry);
    const consumes = s.calls.filter((c) => c === "consume").length;
    // Время решения — свойство вызова, не решения: сравнивается всё, кроме decided_in_ms.
    expect({ ...(await s.adp.decide(retry)), decided_in_ms: 0 }).toEqual({ ...d1, decided_in_ms: 0 });
    expect(s.calls.filter((c) => c === "consume").length).toBe(consumes);
  });

  it("отказ резерва по действующей ссылке — LIMIT_EXCEEDED, ссылка не погашена (погашение — только после резерва)", async () => {
    const s = setup();
    const big = auth({ amount: LIMIT + 1, order_ref: "ORD-big" });
    const r: ConfirmationRecord = {
      confirmation_id: newConfirmationId(),
      agent_code: AGENT,
      mandate_id: M,
      merchant_id: "MER-1042",
      amount: LIMIT + 1,
      currency: "RUB",
      order_ref: "ORD-big",
      split_detected: false,
      status: "PENDING",
      created_at: new Date(T0).toISOString(),
      expires_at: new Date(T0 + HOLD_SEC * 1000).toISOString(),
      confirmation_ref: null,
      decision: null,
      op_ref: null,
    };
    await s.inner.create(r);
    const ref = await s.approve(r);
    const d = pair(await s.adp.decide({ ...big, confirmation_ref: ref }));
    expect(d).toMatchObject({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    expect((await s.inner.byRef(ref))?.status).toBe("APPROVED");
    expect(s.calls).not.toContain("consume");
  });

  it("ссылку погасила другая авторизация между проверкой и погашением — освобождение и CONFIRMATION_REQUIRED", async () => {
    const s = setup({ over: { consume: async () => false } });
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const d = pair(await s.adp.decide(auth({ confirmation_ref: await s.approve(r!) })));
    expect(d).toMatchObject({ decision: "CONFIRMATION_REQUIRED", split_detected: false });
    expect(await s.available(), "удержание проигравшей освобождено (инвариант 4)").toBe(LIMIT);
  });
});

describe("порядок погашений (РП50 п. 10; ворота К1 № 7)", () => {
  it("отзыв между резервом и сверкой статуса при действующей ссылке — отказ, ссылка не погашена", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const ref = await s.approve(r!);
    s.journal.revokeAtRead(3);
    const d = pair(await s.adp.decide(auth({ confirmation_ref: ref })));
    expect(d).toMatchObject({ decision: "DECLINE", reason: "MANDATE_REVOKED" });
    expect((await s.inner.byRef(ref))?.status, "ссылка погашена до сверки статуса").toBe("APPROVED");
    expect(await s.available()).toBe(LIMIT);
  });

  it("реквизит гасится после подтверждения: к погашению криптограммы ссылка уже USED", async () => {
    let seen: string | undefined;
    const box: { store?: MemoryConfirmationStore } = {};
    let ref = "";
    const s = setup({
      credentials: {
        ...agentTokenCredentials,
        consume: async (credential_ref, op_ref) => {
          seen = (await box.store!.byRef(ref))?.status;
          return agentTokenCredentials.consume(credential_ref, op_ref);
        },
      },
    });
    box.store = s.inner;
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    ref = await s.approve(r!);
    expect(pair(await s.adp.decide(auth({ confirmation_ref: ref }))).decision).toBe("APPROVE");
    expect(seen, "погашение реквизита раньше погашения подтверждения").toBe("USED");
  });

  it("хранилище: погашение после срока не проходит (условие consume, а не только проверка ADP)", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const ref = await s.approve(r!);
    expect(await s.inner.consume(ref, "OPKC-late", r!.expires_at)).toBe(false);
    expect(await s.inner.consume(ref, "OPKC-in-time", new Date(Date.parse(r!.expires_at) - 1).toISOString())).toBe(true);
  });
});

describe("сбои П6 — не подтверждено (A3 п. 4.5, РП50 п. 3, 8, 10)", () => {
  it("чтение ссылки не удалось — STATE_UNAVAILABLE до резерва", async () => {
    const s = setup();
    s.broken.add("byRef");
    expect(pair(await s.adp.decide(auth({ confirmation_ref: newConfirmationRef() })))).toMatchObject({ decision: "DECLINE", reason: "STATE_UNAVAILABLE" });
    expect(await s.available()).toBe(LIMIT);
  });

  it("запрос не записан (чтение ключа или вставка) — STATE_UNAVAILABLE", async () => {
    for (const m of ["byKey", "create"]) {
      const s = setup();
      s.broken.add(m);
      expect(pair(await s.adp.decide(auth())), m).toMatchObject({ decision: "DECLINE", reason: "STATE_UNAVAILABLE" });
    }
  });

  it("погашение не записано — освобождение и STATE_UNAVAILABLE", async () => {
    const s = setup();
    await s.adp.decide(auth());
    const [r] = await s.requests(auth());
    const ref = await s.approve(r!);
    s.broken.add("consume");
    expect(pair(await s.adp.decide(auth({ confirmation_ref: ref })))).toMatchObject({ decision: "DECLINE", reason: "STATE_UNAVAILABLE" });
    expect(await s.available()).toBe(LIMIT);
  });

  it("BYPASS П6 не читает (инвариант 2)", async () => {
    const s = setup();
    for (const m of ["byRef", "byKey", "create", "consume", "expire"]) s.broken.add(m);
    const plain = { ...auth({ confirmation_ref: newConfirmationRef() }), instrument: { kind: "CARD_TOKEN" as const, token_ref: "tok_card_1" } };
    delete plain.aoi;
    expect(pair(await s.adp.decide(plain)).decision).toBe("BYPASS");
    expect(s.calls).toEqual([]);
  });

  it("П6 не подключён — как до PS-19: ссылка не проверяется, выше порога CONFIRMATION_REQUIRED", async () => {
    const s = setup({ connected: false });
    expect(pair(await s.adp.decide(auth({ confirmation_ref: newConfirmationRef() }))).decision).toBe("CONFIRMATION_REQUIRED");
    expect(s.calls).toEqual([]);
  });
});

describe("подтверждённая доля (ПС12, РП44 п. 2, 6; РП50 п. 7)", () => {
  it("доля → CONFIRMATION_REQUIRED (split) и запрос; по ссылке — APPROVE, в окно не входит", async () => {
    const s = setup({ splitMinOps: 2 });
    const part = { amount: 170_000 };
    expect(pair(await s.adp.decide(auth({ ...part, order_ref: "ORD-1" }))).decision).toBe("APPROVE");
    const second = auth({ ...part, order_ref: "ORD-2" });
    expect(pair(await s.adp.decide(second))).toMatchObject({ decision: "CONFIRMATION_REQUIRED", split_detected: true });
    const [r] = await s.requests(second);
    expect(r?.split_detected).toBe(true);
    const ref = await s.approve(r!);
    expect(pair(await s.adp.decide(auth({ ...part, order_ref: "ORD-2", confirmation_ref: ref }))).decision).toBe("APPROVE");
    // Вошла бы в окно: 1 700 + 1 700 + 100 > 3 000 — третья была бы долей. Не вошла — 1 700 + 100 ≤ 3 000.
    expect(pair(await s.adp.decide(auth({ amount: 10_000, order_ref: "ORD-3" }))).decision, "одобренная по ссылке вошла в окно").toBe("APPROVE");
  });
});

describe("снимок входа (Р-205)", () => {
  it("изменение сообщения вызывающим после вызова не меняет итоговые значения запроса", async () => {
    const s = setup();
    const m = auth();
    const p = s.adp.decide(m);
    m.amount = 1;
    m.order_ref = "ORD-swapped";
    expect(pair(await p).decision).toBe("CONFIRMATION_REQUIRED");
    const [r] = await s.requests({ ...m, amount: 340_000, order_ref: "ORD-77a1" });
    expect(r).toMatchObject({ amount: 340_000, order_ref: "ORD-77a1" });
  });
});
