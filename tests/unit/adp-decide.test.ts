// П4 точка решения ADP (PS-10, РП43): BYPASS первой проверкой до ввода-вывода (инвариант 2), признак и агент (SPEC §6
// п. 1–4), неподтверждённое состояние — отказ (A3 п. 4.5). Каждое решение — согласованная пара (parseDecision, РП19).
import { describe, expect, it } from "vitest";
import { Adp, isBypass, type AdpAgents } from "../../src/adp/index.js";
import type { AgentStatus } from "../../src/registry/model.js";
import type {
  CanonicalMessage,
  Decision,
} from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";

const AGENT = "nspk:agent:buyref-01:v3";

const msg = (over: Partial<CanonicalMessage> = {}): CanonicalMessage => ({
  op_ref: "OPKC-20261019-000001",
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount: 189_000,
  currency: "RUB",
  merchant: { id: "MER-1042", mcc: "5462" },
  instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
  aoi: { indicator: true, agent_code: AGENT, mandate_id: "mnd_1" },
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

function setup(phase: 1 | 2 | 3 = 3) {
  const agents = new Agents();
  const logs: { fields: Record<string, unknown>; msg: string }[] = [];
  const adp = new Adp({
    agents,
    params: { aoi_rollout_phase: phase },
    log: (_l, fields, m) => logs.push({ fields, msg: m }),
  });
  return { adp, agents, logs };
}

/** Решение ADP — только согласованная пара (РП19); иначе parseDecision бросает. */
const pair = (d: Decision) => parseDecision(d, "adp");

describe("BYPASS — первая проверка (РП4, РП43 п. 1, инвариант 2)", () => {
  it("нет aoi и CARD_TOKEN — BYPASS / null без обращения к реестру", async () => {
    const { adp, agents } = setup();
    agents.failing = true;
    const d = await adp.decide(plain());
    expect(pair(d)).toEqual({ decision: "BYPASS", reason: null });
    expect(agents.calls).toBe(0);
  });

  it("aoi: null — как отсутствие признака: BYPASS", async () => {
    const { adp, agents } = setup();
    agents.failing = true;
    expect(
      pair(await adp.decide(msg({ aoi: null as unknown as undefined })))
        .decision,
    ).toBe("BYPASS");
  });

  it("BYPASS не зависит от остального тела: сумма и продавец не разбираются", async () => {
    const { adp } = setup();
    const odd = {
      ...plain(),
      amount: -1,
      currency: "??",
      merchant: undefined,
    } as unknown as CanonicalMessage;
    expect(pair(await adp.decide(odd)).decision).toBe("BYPASS");
  });

  it("isBypass — только по aoi и виду инструмента", () => {
    expect(isBypass({ instrument: { kind: "CARD_TOKEN" } })).toBe(true);
    expect(isBypass({ instrument: { kind: "AGENT_TOKEN" } })).toBe(false);
    expect(isBypass({ instrument: { kind: "ACCOUNT_LINK" } })).toBe(false);
    expect(
      isBypass({
        instrument: { kind: "CARD_TOKEN" },
        aoi: { indicator: false },
      }),
    ).toBe(false);
  });
});

describe("признак (SPEC §6 п. 1, A1 п. 3.2, РП43 п. 2)", () => {
  it("неизвестный вид инструмента без aoi — AOI_MISSING и инцидент, не BYPASS", async () => {
    const { adp, logs } = setup();
    const d = await adp.decide(
      plain({ instrument: { kind: "NEW_KIND" as "CARD_TOKEN" } }),
    );
    expect(pair(d)).toEqual({ decision: "DECLINE", reason: "AOI_MISSING" });
    expect(logs.some((l) => l.fields.incident === true)).toBe(true);
  });

  it.each(["AGENT_TOKEN", "ACCOUNT_LINK"] as const)(
    "%s без aoi, очередь 3 — AOI_MISSING (ПС07)",
    async (kind) => {
      const { adp } = setup(3);
      expect(pair(await adp.decide(plain({ instrument: { kind } })))).toEqual({
        decision: "DECLINE",
        reason: "AOI_MISSING",
      });
    },
  );

  it.each([1, 2] as const)(
    "AGENT_TOKEN без aoi, очередь %i — домен токена не подключён (PS-14): CREDENTIAL_INVALID",
    async (phase) => {
      const { adp } = setup(phase);
      const d = await adp.decide(
        plain({ instrument: { kind: "AGENT_TOKEN" } }),
      );
      expect(pair(d)).toEqual({
        decision: "DECLINE",
        reason: "CREDENTIAL_INVALID",
      });
    },
  );

  it.each([
    ["indicator: false", { indicator: false, agent_code: AGENT }],
    ["без indicator", { agent_code: AGENT }],
    ["без кода агента", { indicator: true }],
    ["код не по форме", { indicator: true, agent_code: "buyref-01" }],
  ])("%s — AOI_MISSING", async (_n, aoi) => {
    const { adp, agents } = setup();
    expect(pair(await adp.decide(msg({ aoi })))).toEqual({
      decision: "DECLINE",
      reason: "AOI_MISSING",
    });
    expect(agents.calls).toBe(0);
  });
});

describe("агент — из реестра (SPEC §6 п. 3, A1 п. 5.3, инвариант 5)", () => {
  it("нет в реестре — AGENT_UNKNOWN", async () => {
    const { adp, agents } = setup();
    agents.map.clear();
    expect(pair(await adp.decide(msg()))).toEqual({
      decision: "DECLINE",
      reason: "AGENT_UNKNOWN",
    });
  });

  it("EXCLUDED — AGENT_UNKNOWN (вне реестра), SUSPENDED — AGENT_SUSPENDED", async () => {
    const { adp, agents } = setup();
    agents.map.set(AGENT, "EXCLUDED");
    expect(pair(await adp.decide(msg())).reason).toBe("AGENT_UNKNOWN");
    agents.map.set(AGENT, "SUSPENDED");
    expect(pair(await adp.decide(msg())).reason).toBe("AGENT_SUSPENDED");
  });

  it("сбой реестра — STATE_UNAVAILABLE, не BYPASS (РП43 п. 4)", async () => {
    const { adp, agents } = setup();
    agents.failing = true;
    expect(pair(await adp.decide(msg()))).toEqual({
      decision: "DECLINE",
      reason: "STATE_UNAVAILABLE",
    });
  });

  it("агентский токен с aoi до PS-14 — CREDENTIAL_INVALID (проверки 2 и 4 не подтверждены, РП43 п. 7)", async () => {
    const { adp } = setup();
    const d = await adp.decide(
      msg({ instrument: { kind: "AGENT_TOKEN", token_ref: "tok_ag_1" } }),
    );
    expect(pair(d)).toEqual({
      decision: "DECLINE",
      reason: "CREDENTIAL_INVALID",
    });
  });
});
