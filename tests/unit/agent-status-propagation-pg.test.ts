// Распространение приостановления на PostgreSQL (PS-17, РП54 п. 3; инвариант 8): ADP на PG-хранилищах (реквизиты, записи
// операций, удержания) и проверка обращения ПАО с nonce на PG; реестр — в памяти, как в рабочем сервере до переезда
// (жёсткое условие РП54 п. 3). Приостановление — службой статуса с событием в ленте PG; первая авторизация и первое
// обращение после возврата — AGENT_SUSPENDED не позже revocation_propagation_max_ms; снятие — так же. Между экземплярами
// не проверяется: реестр в памяти процесса. В памяти тот же замер — tests/scenarios/ps25.test.ts.
// В CI (РП30 п. 7); локально без базы — пропуск.
import { performance } from "node:perf_hooks";
import { PgHoldLedger, signRequest, type HttpLike } from "@kuzin4u/agentic-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Adp, PgOperationStore, type AdpMandate, type AdpMandates } from "../../src/adp/index.js";
import { PgConsentStore } from "../../src/consent/store.js";
import { opaqueRef, PgCredentialStore, sha256Hex } from "../../src/credentials/index.js";
import { agentStatusEventIdFor } from "../../src/pao/events.js";
import { PaoRequestVerifier, paoNonceStore, type PaoAuthResult, type PaoRequest } from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, AgentStatusService, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { loadParams } from "../../src/shared/config.js";
import { StateService, type MandateBudget, type MandateBudgetSource } from "../../src/state/index.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const params = loadParams();
const AGENT = "nspk:agent:prop-pg:v1";
const ROOT = "mnd_00000000-0000-4000-8000-00000000a001";
const M = "mnd_00000000-0000-4000-8000-00000000a002";
const VALID_TO = "2099-01-01T00:00:00.000Z";
const client = { participant_code: "bank:pg", principal_ref: "prn_prop" };

class Mandates implements AdpMandates, MandateBudgetSource {
  readonly map = new Map<string, AdpMandate>([
    [ROOT, { status: "ACTIVE", type: "INTENT", merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: 10_000_000, client }],
    [M, { status: "ACTIVE", type: "CART", parent_id: ROOT, merchant_scope: ["MER-1042"], currency: "RUB", amount_limit: 1_000_000, client }],
  ]);
  async get(id: string, agent_code: string): Promise<AdpMandate | undefined> {
    return agent_code === AGENT ? this.map.get(id) : undefined;
  }
  async budget(id: string): Promise<MandateBudget | undefined> {
    const m = this.map.get(id);
    return m && { status: "ACTIVE", amount_limit: m.amount_limit, currency: m.currency };
  }
}

describe.skipIf(!DATABASE_URL)("распространение приостановления на PostgreSQL (РП54 п. 3, инвариант 8)", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("agent_prop");
  });
  afterAll(async () => {
    await db?.close();
  });

  it("приостановление → AGENT_SUSPENDED в ADP и шлюзе ≤ revocation_propagation_max_ms; снятие → APPROVE и проверка обращения проходит; событие — в ленте PG", async () => {
    const max = params.revocation_propagation_max_ms;
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const side = newAgentSide();
    expect(registry.admit(buyerApplication(AGENT, side), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
    const events = new PgConsentStore(db.pool);
    // Подписки нет — строк попытки push нет; доставка — tests/unit/agent-status.test.ts.
    const service = new AgentStatusService(registry, { events, pushFor: () => false });
    const gateway = new PaoRequestVerifier(
      { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec, nonces: paoNonceStore({ client: db.pool, skewSec: params.signature_skew_sec }) },
    );
    const mandates = new Mandates();
    const credentials = new PgCredentialStore(db.pool);
    const adp = new Adp({
      agents: registry,
      mandates,
      clientLimits: { get: async () => [] },
      state: new StateService(new PgHoldLedger(db.pool), mandates, { reservationTtlSec: 600 }),
      operations: new PgOperationStore(db.pool, { lockTimeoutMs: 5_000 }),
      credentials,
      params: { aoi_rollout_phase: 3, confirm_above_kop: 1_000_000, split_window_sec: 600, split_min_ops: 21, client_limit_period_tz: "Europe/Moscow" },
    });

    const token_ref = opaqueRef("tok_ag_");
    const now = new Date().toISOString();
    await credentials.putToken({ token_ref, agent_code: AGENT, mandate_id: M, merchant_scope: ["MER-1042"], valid_to: VALID_TO, funding_ref: "fnd_pg", created_at: now, merchant_mcc: { "MER-1042": ["5462"] } });
    let n = 0;
    /** Реквизит, выданный «сейчас» (после возможного снятия — отсечка его не касается), и сообщение по нему. */
    const message = async (): Promise<CanonicalMessage> => {
      const cryptogram = `cg-prop-${++n}`;
      await credentials.putCredential({
        credential_ref: opaqueRef("crd_"),
        agent_code: AGENT,
        mandate_id: M,
        token_ref,
        order_ref: opaqueRef("ORD-"),
        merchant_id: "MER-1042",
        amount_max: 10_000,
        currency: "RUB",
        valid_to: VALID_TO,
        cryptogram_sha256: sha256Hex(cryptogram),
        status: "ISSUED",
        op_ref: null,
        created_at: new Date().toISOString(),
      });
      return {
        op_ref: `OPKC-PROP-PG-${n}`,
        msg_type: "AUTH_REQUEST",
        channel: "CARD",
        amount: 10_000,
        currency: "RUB",
        merchant: { id: "MER-1042", mcc: "5462" },
        instrument: { kind: "AGENT_TOKEN", token_ref, cryptogram },
        aoi: { indicator: true, agent_code: AGENT, mandate_id: M },
      };
    };
    const signedRequest = (): PaoRequest => {
      const req: HttpLike = {
        method: "GET",
        path: "/pao/v1/events",
        query: "",
        headers: { "x-agent-code": AGENT, "x-timestamp": new Date().toISOString().slice(0, 19) + "Z", "x-nonce": `prop-${process.pid}-${++n}` },
        body: "",
      };
      const s = signRequest(req, side.signer);
      return { method: s.method, path: s.path, query: s.query ?? "", headers: s.headers, body: s.body ?? "" };
    };
    const result = (r: PaoAuthResult) => (r.ok ? "OK" : r.code);

    const before = await message();
    // Отсечка делит время по миллисекундам: приостановление — заведомо позже реквизита before.
    await new Promise((r) => setTimeout(r, 5));
    // Сообщение и обращение готовы заранее: в замер входят только действие оператора и решение.
    let msg = await message();
    let req = signedRequest();
    let start = performance.now();
    await service.suspend(AGENT, "KEY_COMPROMISE");
    expect(parseDecision(await adp.decide(msg), "adp")).toEqual({ decision: "DECLINE", reason: "AGENT_SUSPENDED" });
    expect(performance.now() - start, "приостановление → отказ ADP").toBeLessThanOrEqual(max);
    expect(result(await gateway.verify(req))).toBe("AGENT_SUSPENDED");
    expect(performance.now() - start, "приостановление → отказ шлюза").toBeLessThanOrEqual(max);

    // Повтор действия — без второго события; событие в ленте PG.
    await service.suspend(AGENT, "KEY_COMPROMISE");
    expect((await events.listEvents(AGENT, undefined, 10)).map((e) => [e.type, e.event_id])).toEqual([["agent.suspended", agentStatusEventIdFor(AGENT, 2)]]);

    // Отсечка (РП54 п. 5) делит время по миллисекундам: следующий реквизит — заведомо позже приостановления.
    await new Promise((r) => setTimeout(r, 5));
    msg = await message();
    req = signedRequest();
    start = performance.now();
    await service.reinstate(AGENT);
    expect(parseDecision(await adp.decide(msg), "adp")).toEqual({ decision: "APPROVE", reason: null });
    expect(performance.now() - start, "снятие → одобрение ADP").toBeLessThanOrEqual(max);
    expect(result(await gateway.verify(req))).toBe("OK");
    expect(performance.now() - start, "снятие → проверка обращения").toBeLessThanOrEqual(max);
    // Реквизит до приостановления — отсечка и на PG-хранилище реквизитов.
    expect(parseDecision(await adp.decide(before), "adp")).toEqual({ decision: "DECLINE", reason: "CREDENTIAL_INVALID" });
    expect((await events.listEvents(AGENT, undefined, 10)).map((e) => e.type)).toEqual(["agent.suspended", "agent.reinstated"]);
  });
});
