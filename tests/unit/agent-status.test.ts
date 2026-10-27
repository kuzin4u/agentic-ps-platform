// Приостановление и снятие агента (PS-17, РП54 п. 1–2, 8–10) на стенде в памяти: одно действие оператора — статус и
// событие agent.suspended / agent.reinstated с data {agent_code}; agent.suspended push-ем и при SUSPENDED (п. 9), прочие
// события — только в ленте; повтор действия не удваивает событие; сбой записи события — статус остаётся, повтор дописывает.
// ПС25 целиком (ADP, реквизиты, распространение) — tests/scenarios/ps25.test.ts.
import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { issuedBeforeSuspension } from "../../src/adp/decide.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { agentStatusEventIdFor, pushAllowed } from "../../src/pao/events.js";
import {
  AgentRegistry,
  AgentStatusEventMissingError,
  AgentStatusService,
  InMemoryAgentRegistryStore,
  StatusTransitionError,
} from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Event, MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { STAND_AGENT_EMULATOR_HOST } from "../../src/stand/dns.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const T0 = new Date("2026-10-23T10:00:00Z");
const URL_OK = `https://${STAND_AGENT_EMULATOR_HOST}/pao/events`;

describe("приостановление и снятие агента на стенде (РП54)", () => {
  let stand: Stand;
  beforeEach(() => {
    stand = createStand();
    stand.setClock(T0);
  });
  afterAll(async () => stand?.close());

  async function agent(events: Event["type"][] = ["agent.suspended", "agent.reinstated", "mandate.signed"]) {
    const code = `nspk:agent:susp-${randomUUID().slice(0, 8)}:v1`;
    const side = newAgentSide();
    expect((await stand.admit(buyerApplication(code, side), "op")).admitted).toBe(true);
    const call = (c: Parameters<typeof signedInject>[3]) => signedInject(stand.app, side, code, { now: stand.now(), ...c });
    const put = await call({
      method: "PUT",
      path: "/pao/v1/subscription",
      body: JSON.stringify({ url: URL_OK, events }),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(put.statusCode).toBe(200);
    const mandate = async (): Promise<string> => {
      const req: MandateRequest = {
        type: "INTENT",
        subject: "s",
        amount_limit: 1_000,
        currency: "RUB",
        valid_to: "2026-10-30T00:00:00Z",
        merchant_scope: ["MER-1042"],
        principal_ref: "prn_susp",
        mode: "IMMEDIATE",
      };
      const r = await call({ method: "POST", path: "/pao/v1/mandates", body: JSON.stringify(req), headers: { "idempotency-key": randomUUID() } });
      expect(r.statusCode).toBe(201);
      return (r.json() as { id: string }).id;
    };
    const feed = async (): Promise<Event[]> => {
      const r = await call({ method: "GET", path: "/pao/v1/events" });
      expect(r.statusCode).toBe(200);
      return r.json() as Event[];
    };
    return { code, side, call, mandate, feed };
  }

  const decide = async (m: CanonicalMessage) =>
    parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json(), "adp");

  it("отсечка реквизита (РП54 п. 5): выданный до приостановления — CREDENTIAL_INVALID и после снятия; выданный после — APPROVE", async () => {
    const a = await agent([]);
    const pay = standPay(stand, a.side, a.code, "prn_cut");
    const cart = await pay.cart(await pay.mandate({ amount_limit: 100_000 }), 50_000);
    const before = await pay.auth(cart, 10_000);

    stand.setClock(new Date(T0.getTime() + 1_000));
    await stand.suspendAgent(a.code, "KEY_COMPROMISE");
    expect(await decide({ ...before, op_ref: "OPKC-CUT-1" })).toEqual({ decision: "DECLINE", reason: "AGENT_SUSPENDED" });

    stand.setClock(new Date(T0.getTime() + 2_000));
    await stand.reinstateAgent(a.code);
    // Отказ на п. 3 криптограмму не погасил, но и после снятия реквизит не действует.
    expect(await decide({ ...before, op_ref: "OPKC-CUT-2" })).toEqual({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    expect(await decide(await pay.auth(cart, 10_000, "OPKC-CUT-3"))).toEqual({ decision: "APPROVE", reason: null });
  });

  it("равенство отсечки (Р-634; РП64 дополнение «2б-2» п. 1): реквизит той же миллисекунды, что приостановление, — CREDENTIAL_INVALID после снятия", async () => {
    const a = await agent([]);
    const pay = standPay(stand, a.side, a.code, "prn_cut_eq");
    const cart = await pay.cart(await pay.mandate({ amount_limit: 100_000 }), 50_000);
    // Реквизит и приостановление — в один момент T0: метки равны.
    const same = await pay.auth(cart, 10_000);
    await stand.suspendAgent(a.code, "KEY_COMPROMISE");
    stand.setClock(new Date(T0.getTime() + 1_000));
    await stand.reinstateAgent(a.code);
    expect(await decide({ ...same, op_ref: "OPKC-CUT-EQ-1" })).toEqual({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    expect(issuedBeforeSuspension(T0.toISOString(), T0.toISOString())).toBe(true);
    expect(issuedBeforeSuspension(new Date(T0.getTime() + 1).toISOString(), T0.toISOString())).toBe(false);
  });

  it("приостановление: статус, 403 на ленте, agent.suspended push-ем приостановленному; data — только {agent_code}", async () => {
    const a = await agent();
    const rec = await stand.suspendAgent(a.code, "KEY_COMPROMISE");
    expect(rec).toMatchObject({ status: "SUSPENDED", status_ground: "KEY_COMPROMISE", suspended_at: T0.toISOString(), row_version: 2 });
    expect(((await a.call({})).json() as { status: string }).status).toBe("SUSPENDED");
    const feed = await a.call({ method: "GET", path: "/pao/v1/events" });
    expect(feed.statusCode).toBe(403);
    expect((feed.json() as { code: string }).code).toBe("AGENT_SUSPENDED");

    expect(await stand.deliverEvents()).toBe(1);
    const [got] = stand.agentReceiver.handled;
    expect(got).toEqual({
      event_id: agentStatusEventIdFor(a.code, 2),
      type: "agent.suspended",
      at: T0.toISOString(),
      data: { agent_code: a.code },
    });
  });

  it("при SUSPENDED прочие события только в ленте: push не создаётся; после снятия — лента по порядку, push по накопленным не догоняет", async () => {
    const a = await agent();
    const id = await a.mandate();
    await stand.suspendAgent(a.code, "OUT_OF_MANDATE");
    // Банк подписывает мандат во время приостановления — событие пишется, но push нет (РП40 п. 6).
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    expect(await stand.deliverEvents()).toBe(1); // только agent.suspended
    expect(stand.agentReceiver.handled.map((e) => e.type)).toEqual(["agent.suspended"]);

    stand.setClock(new Date(T0.getTime() + 60_000));
    const back = await stand.reinstateAgent(a.code);
    expect(back).toMatchObject({ status: "ACTIVE", status_ground: null, suspended_at: T0.toISOString(), row_version: 3 });
    expect((await a.feed()).map((e) => [e.type, e.data])).toEqual([
      ["agent.suspended", { agent_code: a.code }],
      ["mandate.signed", { mandate_id: id }],
      ["agent.reinstated", { agent_code: a.code }],
    ]);
    expect(await stand.deliverEvents()).toBe(1); // agent.reinstated; mandate.signed не догоняет
    expect(stand.agentReceiver.handled.map((e) => e.type)).toEqual(["agent.suspended", "agent.reinstated"]);
  });

  it("повтор действия в достигнутом статусе — без второго события; другое основание и снятие с допуска — отказ", async () => {
    const a = await agent([]);
    await expect(stand.reinstateAgent(a.code)).rejects.toThrow(StatusTransitionError);
    await stand.suspendAgent(a.code, "KEY_COMPROMISE");
    expect(await stand.suspendAgent(a.code, "KEY_COMPROMISE")).toMatchObject({ status: "SUSPENDED", row_version: 2 });
    await expect(stand.suspendAgent(a.code, "OUT_OF_MANDATE")).rejects.toThrow(StatusTransitionError);
    await expect(stand.suspendAgent(a.code, "UNKNOWN_GROUND")).rejects.toThrow(StatusTransitionError);
    await stand.reinstateAgent(a.code);
    expect(await stand.reinstateAgent(a.code)).toMatchObject({ status: "ACTIVE", row_version: 3 });
    expect((await a.feed()).map((e) => e.type)).toEqual(["agent.suspended", "agent.reinstated"]);
  });

  it("исключённого агента служба не приостанавливает и не восстанавливает (РП21 п. 4)", async () => {
    const a = await agent([]);
    await stand.registry.changeStatus(a.code, { to: "EXCLUDED", ground: "WITHDRAWN" });
    await expect(stand.suspendAgent(a.code, "KEY_COMPROMISE")).rejects.toThrow(StatusTransitionError);
    await expect(stand.reinstateAgent(a.code)).rejects.toThrow(StatusTransitionError);
  });
});

describe("сбой записи события статуса (РП54 п. 2)", () => {
  const params = loadParams();
  it("статус остаётся SUSPENDED, ошибка вызывающему с инцидентом; повтор того же действия дописывает событие один раз", async () => {
    const registry = new AgentRegistry(new InMemoryAgentRegistryStore(), { keys: params, now: () => T0 });
    const code = "nspk:agent:susp-fail:v1";
    expect((await registry.admit(buyerApplication(code, newAgentSide()), { contour: "sandbox", operator: "op" })).admitted).toBe(true);
    const store = new MemoryConsentStore();
    let broken = true;
    const logs: Record<string, unknown>[] = [];
    const service = new AgentStatusService(registry, {
      events: {
        appendAgentStatusEvent: (d, at) => (broken ? Promise.reject(new Error("лента недоступна")) : store.appendAgentStatusEvent(d, at)),
      },
      pushFor: async () => false,
      log: (_l, f) => logs.push(f),
    });

    await expect(service.suspend(code, "KEY_COMPROMISE")).rejects.toThrow(AgentStatusEventMissingError);
    expect((await registry.get(code))?.status).toBe("SUSPENDED");
    expect(logs).toContainEqual(expect.objectContaining({ code: "AGENT_STATUS_EVENT_MISSING", incident: true }));
    expect(await store.listEvents(code, undefined, 10)).toEqual([]);

    broken = false;
    await service.suspend(code, "KEY_COMPROMISE");
    await service.suspend(code, "KEY_COMPROMISE");
    const events = await store.listEvents(code, undefined, 10);
    expect(events.map((e) => [e.type, e.event_id, e.at])).toEqual([["agent.suspended", agentStatusEventIdFor(code, 2), T0.toISOString()]]);
  });

  it("с транзакцией реестра (РП64 п. 4) — одно обращение transitStatus с действием оператора; events, pushFor и changeStatus не вызываются", async () => {
    const registry = new AgentRegistry(new InMemoryAgentRegistryStore(), { keys: params, now: () => T0 });
    const unused = () => {
      throw new Error("не должно вызываться при tx");
    };
    const calls: unknown[] = [];
    const service = new AgentStatusService(registry, {
      events: { appendAgentStatusEvent: unused },
      pushFor: unused,
      tx: {
        transitStatus: async (agent_code, req) => {
          calls.push([agent_code, req]);
          return { record: { agent_code } as never, written: true };
        },
      },
    });
    // Агента в памяти нет: путь без транзакции дал бы AgentNotFoundError.
    expect((await service.suspend("nspk:agent:tx-only:v1", "KEY_COMPROMISE")).agent_code).toBe("nspk:agent:tx-only:v1");
    expect((await service.reinstate("nspk:agent:tx-only:v1")).agent_code).toBe("nspk:agent:tx-only:v1");
    expect(calls).toEqual([
      ["nspk:agent:tx-only:v1", { to: "SUSPENDED", ground: "KEY_COMPROMISE" }],
      ["nspk:agent:tx-only:v1", { to: "ACTIVE" }],
    ]);
  });

  it("pushAllowed: ACTIVE — всё; SUSPENDED — только agent.suspended; EXCLUDED и неизвестный — ничего (РП54 п. 9)", () => {
    expect(pushAllowed("ACTIVE", "mandate.signed")).toBe(true);
    expect(pushAllowed("SUSPENDED", "agent.suspended")).toBe(true);
    expect(pushAllowed("SUSPENDED", "agent.reinstated")).toBe(false);
    expect(pushAllowed("SUSPENDED", "operation.declined")).toBe(false);
    expect(pushAllowed("EXCLUDED", "agent.suspended")).toBe(false);
    expect(pushAllowed(undefined, "agent.suspended")).toBe(false);
  });
});
