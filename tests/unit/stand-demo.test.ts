// РП75 (#112): каркас режима сбоев демо-стенда — включение только faults: true, arm / disarm / mark / log по закрытым
// перечням, часы стенда в журнале, короткий срок подтверждения и удержания в демо-режиме (п. 7а). Граница «рабочий
// сервер без режима» — tests/unit/stand-boundary.test.ts.
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createStand, DEMO_TESTS, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const opened: Stand[] = [];
const open = (o?: Parameters<typeof createStand>[0]): Stand => {
  const s = createStand(o);
  opened.push(s);
  return s;
};
afterEach(async () => {
  await Promise.all(opened.splice(0).map((s) => s.close()));
});

const demoOf = (s: Stand) => {
  if (!s.demo) throw new Error("нет stand.demo");
  return s.demo;
};

describe("РП75 п. 1: режим только при createStand({ demo: { faults: true } })", () => {
  it("без demo и при faults: false — stand.demo нет, срок — order_hold_sec", () => {
    for (const s of [open(), open({ demo: { faults: false } })]) {
      expect(s.demo).toBeUndefined();
      expect("demo" in s).toBe(false);
      expect(s.params.order_hold_sec).toBe(900);
    }
  });

  it("faults: true — stand.demo есть, журнал пуст; срок подтверждения и удержания — demo_order_hold_sec (п. 7а)", () => {
    for (const s of [open({ demo: { faults: true } }), open({ demo: { faults: true, actions: true } })]) {
      expect(demoOf(s).log()).toEqual([]);
      expect(s.params.order_hold_sec).toBe(s.params.demo_order_hold_sec);
      expect(s.params.demo_order_hold_sec).toBe(45);
      expect(Object.isFrozen(s.params)).toBe(true);
    }
  });
});

describe("РП75 дополнение #115 п. 1: опции actions / faults", () => {
  it("demo: {}, { actions: false }, { actions: false, faults: false } — stand.demo нет, срок — order_hold_sec", () => {
    for (const s of [open({ demo: {} }), open({ demo: { actions: false } }), open({ demo: { actions: false, faults: false } })]) {
      expect(s.demo).toBeUndefined();
      expect("demo" in s).toBe(false);
      expect(s.params.order_hold_sec).toBe(900);
    }
  });

  it("faults: true при actions: false — исключение при сборке, стенд не создаётся (Р-1387)", () => {
    expect(() => open({ demo: { faults: true, actions: false } })).toThrow(/сбоев без действий нет/);
  });

  it("actions: true — stand.demo с действиями, срок — order_hold_sec (900 с); arm / disarm / mark — исключение, записи нет", () => {
    const s = open({ demo: { actions: true } });
    const d = demoOf(s);
    expect(s.params.order_hold_sec).toBe(900);
    for (const m of ["stopPurchase", "remindClient", "revokeMandate", "sendToReview", "log"] as const) expect(typeof d[m]).toBe("function");
    expect(() => d.arm("Н-02")).toThrow(/сбои выключены/);
    expect(() => d.disarm("Н-02")).toThrow(/сбои выключены/);
    expect(() => d.mark("Н-06", { mandate_id: "mnd_1" })).toThrow(/сбои выключены/);
    expect(d.log()).toEqual([]);
  });

  it("п. 4а: «только действия» — cryptogram_ttl_sec = order_hold_sec + confirmation_remind_extend_sec; сбои и без режима — прежний", () => {
    const plain = open();
    expect(plain.params.cryptogram_ttl_sec).toBe(900);
    expect(open({ demo: { faults: true } }).params.cryptogram_ttl_sec).toBe(900);
    const s = open({ demo: { actions: true } });
    expect(s.params.cryptogram_ttl_sec).toBe(s.params.order_hold_sec + s.params.confirmation_remind_extend_sec);
    expect(Object.isFrozen(s.params)).toBe(true);
  });

  it("п. 4: продление — 300 с без режима и при «только действия» (реквизит 1 200 с); при faults — demo_confirmation_remind_extend_sec (15 с)", () => {
    expect(open().params.confirmation_remind_extend_sec).toBe(300);
    const only = open({ demo: { actions: true } });
    expect(only.params.confirmation_remind_extend_sec).toBe(300);
    expect(only.params.cryptogram_ttl_sec).toBe(1_200);
    const f = open({ demo: { faults: true } });
    expect(f.params.demo_confirmation_remind_extend_sec).toBe(15);
    expect(f.params.confirmation_remind_extend_sec).toBe(f.params.demo_confirmation_remind_extend_sec);
    expect(f.params.cryptogram_ttl_sec).toBe(900);
  });
});

describe("РП75 п. 2–4: arm / disarm / mark / log", () => {
  it("arm — только сбои вида «П»; повтор — новая запись; disarm — запись только у включённого", () => {
    const s = open({ demo: { faults: true } });
    s.setClock(new Date("2026-11-08T10:00:00Z"));
    const d = demoOf(s);
    for (const t of ["Н-02", "Н-03", "Н-04", "Н-05", "Н-11", "Н-12"] as const) d.arm(t);
    d.arm("Н-12", { delay_ms: 2000 });
    expect(d.disarm("Н-03")).toBe(true);
    expect(d.disarm("Н-03")).toBe(false);
    expect(d.log().map((e) => [e.seq, e.kind, e.test, e.what])).toEqual([
      [1, "fault", "Н-02", "ARMED"],
      [2, "fault", "Н-03", "ARMED"],
      [3, "fault", "Н-04", "ARMED"],
      [4, "fault", "Н-05", "ARMED"],
      [5, "fault", "Н-11", "ARMED"],
      [6, "fault", "Н-12", "ARMED"],
      [7, "fault", "Н-12", "ARMED"],
      [8, "fault", "Н-03", "DISARMED"],
    ]);
    expect(d.log().every((e) => e.at === "2026-11-08T10:00:00.000Z")).toBe(true);
  });

  it.each(["Н-01", "Н-06", "Н-07", "Н-08", "Н-09", "Н-10"] as const)("arm(%s) — не сбой Платформы: исключение, записи нет", (t) => {
    const d = demoOf(open({ demo: { faults: true } }));
    expect(() => d.arm(t)).toThrow(/не сбой Платформы/);
    expect(d.log()).toEqual([]);
  });

  it("неизвестный тест и настройка вне перечня — исключение", () => {
    const d = demoOf(open({ demo: { faults: true } }));
    expect(() => d.arm("Н-13" as never)).toThrow(/неизвестный тест/);
    expect(() => d.disarm("H-02" as never)).toThrow(/неизвестный тест/); // латинская H
    expect(() => d.mark("Н-00" as never, {})).toThrow(/неизвестный тест/);
    expect(() => d.arm("Н-12", { delay: 1 } as never)).toThrow(/настройка delay вне перечня/);
    expect(d.log()).toEqual([]);
  });

  it("mark — только «ПР» (Н-01, Н-05…Н-09), ids — закрытый перечень непустых строк; Н-10 — нельзя (инвариант 1)", () => {
    const s = open({ demo: { faults: true } });
    s.setClock(new Date("2026-11-08T10:05:00Z"));
    const d = demoOf(s);
    d.mark("Н-01", { shop_id: "SHOP-1042", order_id: "ORD-1" });
    d.mark("Н-05", {});
    for (const t of ["Н-06", "Н-07", "Н-08", "Н-09"] as const) d.mark(t, { mandate_id: "m-1" });
    expect(() => d.mark("Н-10", {})).toThrow(/пометка только/);
    expect(() => d.mark("Н-02", {})).toThrow(/пометка только/);
    expect(() => d.mark("Н-01", { credential_ref: "cr-1" } as never)).toThrow(/credential_ref вне перечня/);
    expect(() => d.mark("Н-01", { order_id: "" })).toThrow(/непустая строка/);
    expect(() => d.mark("Н-01", { order_id: 7 } as never)).toThrow(/непустая строка/);
    expect(() => d.mark("Н-01", null as never)).toThrow(/ids — объект/);
    const log = d.log();
    expect(log.map((e) => [e.test, e.what])).toEqual([
      ["Н-01", "MARKED"],
      ["Н-05", "MARKED"],
      ["Н-06", "MARKED"],
      ["Н-07", "MARKED"],
      ["Н-08", "MARKED"],
      ["Н-09", "MARKED"],
    ]);
    expect(log[0]).toEqual({ seq: 1, at: "2026-11-08T10:05:00.000Z", kind: "fault", test: "Н-01", what: "MARKED", ids: { shop_id: "SHOP-1042", order_id: "ORD-1" } });
  });

  it("log — копия, записи заморожены; перечень тестов — Н-01…Н-12", () => {
    const d = demoOf(open({ demo: { faults: true } }));
    d.arm("Н-03");
    const a = d.log();
    (a as unknown[]).push("x");
    expect(d.log()).toHaveLength(1);
    expect(Object.isFrozen(d.log()[0])).toBe(true);
    expect(Object.isFrozen(d.log()[0]!.ids)).toBe(true);
    expect(DEMO_TESTS).toHaveLength(12);
  });

  it("журналы двух стендов не смешиваются", () => {
    const a = demoOf(open({ demo: { faults: true } }));
    const b = demoOf(open({ demo: { faults: true } }));
    a.arm("Н-03");
    expect(b.log()).toEqual([]);
  });
});

describe("РП75 п. 7а: в демо-режиме ADP ставит запросу подтверждения короткий срок", () => {
  const CODE = "nspk:agent:demo-hold:v1";
  const AMOUNT = 340_000;

  async function confirmationExpiry(s: Stand): Promise<string> {
    s.setClock(new Date("2026-11-08T09:00:00Z"));
    const side = newAgentSide();
    expect((await s.admit(buyerApplication(CODE, side), "op")).admitted).toBe(true);
    const call = (method: "GET" | "POST", path: string, body?: unknown) =>
      signedInject(s.app, side, CODE, {
        method,
        path,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        headers: { "idempotency-key": randomUUID() },
        now: s.now(),
      });
    const mandate = async (over: Partial<MandateRequest>): Promise<string> => {
      const req: MandateRequest = {
        type: "INTENT",
        subject: "s",
        amount_limit: 1,
        currency: "RUB",
        valid_to: "2026-11-12T00:00:00Z",
        merchant_scope: ["MER-1042"],
        principal_ref: "prn_demo_hold",
        mode: "IMMEDIATE",
        ...over,
      };
      const res = await call("POST", "/pao/v1/mandates", req);
      expect(res.statusCode).toBe(201);
      const id = (res.json() as { id: string }).id;
      expect((await s.issuer.sign(id)).statusCode).toBe(200);
      return id;
    };
    const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "техника" });
    const cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: 2_000_000,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: "kettle", qty: 1, price: AMOUNT }], total: AMOUNT },
    });
    const order_ref = "ORD-demo-hold-1";
    const cr = await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" });
    expect(cr.statusCode).toBe(201);
    const cred = cr.json() as Credential;
    const msg: CanonicalMessage = {
      op_ref: `OPKC-${order_ref}-1`,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: AMOUNT,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
      aoi: cred.aoi,
      order_ref,
    };
    const d = (await s.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
    expect(d.decision).toBe("CONFIRMATION_REQUIRED");
    const feed = (await call("GET", "/pao/v1/events")).json() as { type: string; data: { confirmation_id?: string } }[];
    const id = feed.at(-1)!.data.confirmation_id!;
    const view = (await call("GET", `/pao/v1/confirmations/${id}`)).json() as { expires_at: string };
    return view.expires_at;
  }

  it("демо-стенд — через demo_order_hold_sec (45 с), обычный — через order_hold_sec (900 с)", async () => {
    expect(await confirmationExpiry(open({ demo: { faults: true } }))).toBe("2026-11-08T09:00:45.000Z");
    expect(await confirmationExpiry(open())).toBe("2026-11-08T09:15:00.000Z");
  });
});
