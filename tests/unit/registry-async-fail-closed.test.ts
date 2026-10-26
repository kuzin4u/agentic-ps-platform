// Асинхронный порт реестра (РП64 п. 3, PS-05в ч. 2б-1): сбой чтения — отклонённое обещание, и каждый читатель отказывает,
// а не догадывается (инвариант 3). ADP, доставка, API продавцов и ключи ПАО — в своих файлах тестов; здесь — проверка
// обращения, сверка продавца, строка push у служб со своей записью и страж точек в транзакции (РП64 нюанс 2б-1 К1 п. 7).
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MemoryConfirmationStore, newConfirmationId, type ConfirmationRecord } from "../../src/confirm/index.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { MemoryOutcomeStore, OperationOutcomeCollector, type OutcomeStore } from "../../src/fulfilment/outcomes.js";
import { PaoRequestVerifier } from "../../src/pao/verify.js";
import { reconcile } from "../../src/participants/payments.js";
import {
  AgentRegistry,
  AgentStatusEventMissingError,
  AgentStatusService,
  InMemoryAgentRegistryStore,
  type AgentKey,
  type AgentRecord,
} from "../../src/registry/index.js";

const CODE = "nspk:agent:async-fail:v1";
const AT = "2026-10-26T10:00:00.000Z";
const down = async (): Promise<never> => {
  throw new Error("реестр недоступен");
};

describe("сбой чтения реестра — отказ (РП64 п. 3, инвариант 3)", () => {
  it("проверка обращения: getAgent отклонён — UPSTREAM_UNAVAILABLE с причиной и в precheck, и в verify", async () => {
    const v = new PaoRequestVerifier({ getAgent: down, lookupKey: down }, { skewSec: 300, nonces: { seen: async () => false, purge: async () => 0 } });
    const req = { method: "GET", path: "/pao/v1/agent", query: "", headers: { "x-agent-code": CODE } };
    const pre = await v.precheck(req);
    expect(pre).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
    expect((pre as { cause?: Error }).cause?.message).toBe("реестр недоступен");
    expect(await v.verify({ ...req, body: "" })).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
  });

  it("сверка продавца: suspendedAt отклонён — сверка отклонена (маршрут отвечает STATE_UNAVAILABLE), не PENDING", async () => {
    const cred = {
      credential_ref: "cred_1",
      agent_code: CODE,
      mandate_id: "mnd_1",
      order_ref: "ORD-1",
      merchant_id: "MER-1042",
      valid_to: "2099-01-01T00:00:00.000Z",
      status: "ISSUED",
      op_ref: null,
      created_at: AT,
    };
    const deps = {
      credentials: { credentialForMerchant: async () => cred as never },
      mandateStatus: async () => "ACTIVE",
      suspendedAt: down,
      now: () => new Date(AT),
    };
    await expect(reconcile(deps, { credential_ref: "cred_1", merchant_id: "MER-1042", order_ref: "ORD-1" } as never)).rejects.toThrow(
      "реестр недоступен",
    );
  });

  it("приостановление: строка push не прочитана — статус сменён, событие не записано, AgentStatusEventMissingError (повтор дописывает)", async () => {
    const store = new InMemoryAgentRegistryStore();
    const record: AgentRecord = {
      agent_code: CODE,
      issuer: "nspk:agent",
      id: "async-fail",
      version: 1,
      operator: "op-a",
      class: "BUYER",
      level: 1,
      status: "ACTIVE",
      status_ground: null,
      model: "m",
      runtime: "r",
      contour: "sandbox",
      conformance_run_ref: null,
      admitted_at: AT,
      status_changed_at: AT,
      suspended_at: null,
      row_version: 1,
    };
    const key: AgentKey = {
      kid: "k1",
      agent_code: CODE,
      alg: "ed25519",
      public_key: "pk",
      valid_from: AT,
      valid_to: "2027-01-24T10:00:00.000Z",
      revoked_at: null,
      row_version: 1,
    };
    await store.insert(record, key);
    const registry = new AgentRegistry(store, { keys: { key_ttl_days: 90, key_overlap_days: 7 } });
    const appended: unknown[] = [];
    const service = new AgentStatusService(registry, {
      events: { appendAgentStatusEvent: async (d) => (appended.push(d), true) },
      pushFor: down,
    });
    await expect(service.suspend(CODE, "OUT_OF_MANDATE")).rejects.toBeInstanceOf(AgentStatusEventMissingError);
    expect((await registry.get(CODE))?.status).toBe("SUSPENDED");
    expect(appended).toEqual([]);
  });

  it("запрос подтверждения в памяти: строка push не прочитана — запроса и события нет", async () => {
    const events = new MemoryConsentStore();
    const store = new MemoryConfirmationStore({ events, pushFor: down });
    const rec: ConfirmationRecord = {
      confirmation_id: newConfirmationId(),
      agent_code: CODE,
      mandate_id: "mnd_00000000-0000-4000-8000-000000000001",
      merchant_id: "MER-1042",
      amount: 340_000,
      currency: "RUB",
      order_ref: "ORD-1",
      split_detected: false,
      status: "PENDING",
      created_at: AT,
      expires_at: "2026-10-26T10:15:00.000Z",
      confirmation_ref: null,
      decision: null,
      op_ref: null,
    };
    await expect(store.create(rec)).rejects.toThrow("реестр недоступен");
    expect(await store.byKey(rec)).toEqual([]);
    expect(await events.listEvents(CODE, undefined, 10)).toEqual([]);

    // Повтор уже записанного запроса реестр не читает — тот же запрос и при сбое, как на PG (КТ1 ч. 2б-1 № 4).
    let up = true;
    const flaky = new MemoryConfirmationStore({ events, pushFor: async () => (up ? false : down()) });
    const first = await flaky.create(rec);
    up = false;
    expect(await flaky.create({ ...rec, confirmation_id: newConfirmationId() })).toEqual(first);
    expect(await events.listEvents(CODE, undefined, 10)).toHaveLength(1);
  });

  it("сборщик итогов: строка push не прочитана — итог не записан, проход считает сбой и не прерывается", async () => {
    const recorded: unknown[] = [];
    const op = { op_ref: "OP-1", agent_code: CODE, decision: { decision: "DECLINE", reason: "LIMIT_EXCEEDED" } };
    const store = {
      pending: async () => [op, { ...op, op_ref: "OP-2" }],
      record: async (o: unknown) => (recorded.push(o), undefined),
      oldestPending: async () => undefined,
    } as unknown as OutcomeStore;
    const c = new OperationOutcomeCollector(store, { horizonSec: 86_400, maxDelaySec: 30, pushFor: down, now: () => Date.parse(AT) });
    expect(await c.runOnce()).toMatchObject({ recorded: 0, failed: 2 });
    expect(recorded).toEqual([]);
  });

  it("сборщик итогов: итог, пропущенный при сбое чтения реестра, записывается следующим проходом — одно событие (КТ1 ч. 2б-1 № 1)", async () => {
    const ops = new MemoryOperationStore();
    expect(await ops.begin("OP-retry", "h", AT)).toBeUndefined();
    await ops.finish({
      op_ref: "OP-retry",
      msg_hash: "h",
      decision: { decision: "DECLINE", reason: "LIMIT_EXCEEDED", reservation_id: null, decided_in_ms: 1 },
      mandate_id: "mnd_x",
      holds: [],
      at: AT,
      facts: { agent_code: CODE } as never,
    });
    const events = new MemoryConsentStore();
    let failures = 1;
    const pushFor = async (): Promise<boolean> => {
      if (failures-- > 0) throw new Error("реестр недоступен");
      return false;
    };
    const c = new OperationOutcomeCollector(new MemoryOutcomeStore(ops, events), { horizonSec: 86_400, maxDelaySec: 30, pushFor, now: () => Date.parse(AT) });
    expect(await c.runOnce()).toMatchObject({ recorded: 0, failed: 1 });
    expect(await events.listEvents(CODE, undefined, 10)).toEqual([]);
    expect(await c.runOnce()).toMatchObject({ recorded: 1, failed: 0 });
    expect((await events.listEvents(CODE, undefined, 10)).map((e) => e.type)).toEqual(["operation.declined"]);
    expect(await c.runOnce()).toMatchObject({ recorded: 0, failed: 0 });
  });
});

describe("страж: точки внутри транзакций — только из тестов (РП64 нюанс 2б-1 К1 п. 7)", () => {
  it("в src точки inTx / inMarkTx объявлены только в своих хранилищах, конструкторы хранилищ — без второго аргумента", () => {
    const root = join(import.meta.dirname, "../../src");
    const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));
    expect(files.length).toBeGreaterThan(50);
    const owners = new Set([join("registry", "store-pg.ts"), join("consent", "store.ts")]);
    const bad: string[] = [];
    for (const f of files) {
      const text = readFileSync(join(root, f), "utf8");
      if (!owners.has(f) && /\binMarkTx\b|\binTx\b|PgAgentRegistryStoreHooks|PgConsentStoreHooks/.test(text)) bad.push(`${f}: точка`);
      if (/new\s+Pg(?:AgentRegistry|Consent)Store\(\s*[^,()]+,/.test(text)) bad.push(`${f}: второй аргумент`);
    }
    expect(bad).toEqual([]);
  });
});
