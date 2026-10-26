// Реестр агентов на PostgreSQL (РП64 п. 1–3, PS-05в ч. 2а): один набор договора порта — на памяти (через асинхронную
// обёртку, локально) и на PG (CI, РП30 п. 7); одновременные изменения с двух пулов и ограничения схемы — только на PG.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AgentCodeTakenError,
  InMemoryAgentRegistryStore,
  KeyTakenError,
  PgAgentRegistryStore,
  type AgentKey,
  type AgentRecord,
  type AgentRegistryStore,
  type AgentRegistryStoreAsync,
} from "../../src/registry/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const T = "2026-10-26T10:00:00.000Z";
const LATER = "2026-10-26T11:00:00.000Z";

const record = (id: string, over: Partial<AgentRecord> = {}): AgentRecord => ({
  agent_code: `nspk:agent:${id}:v1`,
  issuer: "nspk:agent",
  id,
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
  admitted_at: T,
  status_changed_at: T,
  suspended_at: null,
  row_version: 1,
  ...over,
});

const key = (kid: string, agent_code: string, over: Partial<AgentKey> = {}): AgentKey => ({
  kid,
  agent_code,
  alg: "ed25519",
  public_key: `pk-${kid}`,
  valid_from: T,
  valid_to: "2027-01-24T10:00:00.000Z",
  revoked_at: null,
  row_version: 1,
  ...over,
});

/** Синхронное хранилище в памяти за асинхронным портом — эталон договора. */
function asAsync(s: AgentRegistryStore): AgentRegistryStoreAsync {
  return {
    get: async (...a) => s.get(...a),
    agentCodes: async () => s.agentCodes(),
    ownerOf: async (...a) => s.ownerOf(...a),
    insert: async (...a) => s.insert(...a),
    updateStatus: async (...a) => s.updateStatus(...a),
    getKey: async (...a) => s.getKey(...a),
    keysOf: async (...a) => s.keysOf(...a),
    addKey: async (...a) => s.addKey(...a),
    revokeKey: async (...a) => s.revokeKey(...a),
    subscriptionOf: async (...a) => s.subscriptionOf(...a),
    setSubscription: async (...a) => s.setSubscription(...a),
  };
}

let db: TestDb | undefined;
beforeAll(async () => {
  if (DATABASE_URL) db = await openTestDb("registry");
});
afterAll(async () => {
  await db?.close();
});

// Своя метка на тест: одна схема PG на файл, записи разных тестов не пересекаются.
let n = 0;
const uid = (): string => `t${++n}x${Date.now().toString(36)}`;

const variants: [string, () => AgentRegistryStoreAsync][] = [["память", () => asAsync(new InMemoryAgentRegistryStore())]];
if (DATABASE_URL) variants.push(["PostgreSQL", () => new PgAgentRegistryStore((db as TestDb).pool)]);

describe.each(variants)("порт реестра агентов: %s (РП64 п. 1–3)", (_name, make) => {
  it("вставка с первым ключом; чтение записи, ключа, ключей агента, владельца и порядка допуска", async () => {
    const s = make();
    const a = record(uid());
    const b = record(uid());
    await s.insert(a, key(`k-${a.id}`, a.agent_code));
    await s.insert(b, key(`k-${b.id}`, b.agent_code));
    expect(await s.get(a.agent_code)).toEqual(a);
    expect(await s.getKey(`k-${a.id}`)).toEqual(key(`k-${a.id}`, a.agent_code));
    expect(await s.keysOf(a.agent_code)).toEqual([key(`k-${a.id}`, a.agent_code)]);
    expect(await s.ownerOf(a.issuer, a.id)).toBe("op-a");
    expect(await s.ownerOf(a.issuer, `${a.id}-нет`)).toBeUndefined();
    expect(await s.get(`${a.agent_code}-нет`)).toBeUndefined();
    const codes = await s.agentCodes();
    expect(codes.indexOf(a.agent_code)).toBeLessThan(codes.indexOf(b.agent_code));
  });

  it("вставка неделима: код занят, идентификатор у другого оператора, kid занят — ничего не сохранено (РП23 п. 2)", async () => {
    const s = make();
    const a = record(uid());
    await s.insert(a, key(`k-${a.id}`, a.agent_code));
    await expect(s.insert(a, key(`k2-${a.id}`, a.agent_code))).rejects.toThrow(AgentCodeTakenError);
    expect(await s.getKey(`k2-${a.id}`)).toBeUndefined();
    // Другая версия того же идентификатора: другой оператор — занято, тот же — допускается.
    const v2other = record(a.id, { agent_code: `nspk:agent:${a.id}:v2`, version: 2, operator: "op-b" });
    await expect(s.insert(v2other, key(`k3-${a.id}`, v2other.agent_code))).rejects.toThrow(AgentCodeTakenError);
    expect(await s.get(v2other.agent_code)).toBeUndefined();
    const v2 = record(a.id, { agent_code: `nspk:agent:${a.id}:v2`, version: 2 });
    await s.insert(v2, key(`k4-${a.id}`, v2.agent_code));
    expect((await s.get(v2.agent_code))?.version).toBe(2);
    // kid другого агента: запись нового агента тоже не сохраняется.
    const c = record(uid());
    await expect(s.insert(c, key(`k-${a.id}`, c.agent_code))).rejects.toThrow(KeyTakenError);
    expect(await s.get(c.agent_code)).toBeUndefined();
    expect(await s.ownerOf(c.issuer, c.id)).toBeUndefined();
    await expect(s.insert(c, key(`k-${c.id}`, a.agent_code))).rejects.toThrow("Первый ключ не этого агента");
  });

  it("смена статуса — по версии записи: совпала — версия + 1, поля статуса и suspended_at; не совпала — undefined", async () => {
    const s = make();
    const a = record(uid());
    await s.insert(a, key(`k-${a.id}`, a.agent_code));
    const fields = { status: "SUSPENDED", status_ground: "KEY_COMPROMISE", status_changed_at: LATER, suspended_at: LATER } as const;
    const next = await s.updateStatus(a.agent_code, 1, fields);
    expect(next).toEqual({ ...a, ...fields, row_version: 2 });
    expect(await s.get(a.agent_code)).toEqual(next);
    expect(await s.updateStatus(a.agent_code, 1, { ...fields, status: "ACTIVE", status_ground: null })).toBeUndefined();
    expect(await s.updateStatus(`${a.agent_code}-нет`, 1, fields)).toBeUndefined();
  });

  it("новый ключ с сокращением остальных — по версиям ключей и записи агента; kid занят; агента нет (РП23 п. 4)", async () => {
    const s = make();
    const a = record(uid());
    const k1 = key(`k1-${a.id}`, a.agent_code);
    await s.insert(a, k1);
    const end = "2026-11-02T10:00:00.000Z";
    const k2 = key(`k2-${a.id}`, a.agent_code, { valid_from: LATER });
    // Версия агента или ключей устарела, лишний kid в сокращении — false, ничего не изменилось.
    expect(await s.addKey(k2, new Map([[k1.kid, 1]]), new Map([[k1.kid, end]]), 2)).toBe(false);
    expect(await s.addKey(k2, new Map([[k1.kid, 2]]), new Map([[k1.kid, end]]), 1)).toBe(false);
    expect(await s.addKey(k2, new Map(), new Map(), 1)).toBe(false);
    expect(await s.addKey(k2, new Map([[k1.kid, 1]]), new Map([["чужой", end]]), 1)).toBe(false);
    expect(await s.getKey(k2.kid)).toBeUndefined();
    expect(await s.addKey(k2, new Map([[k1.kid, 1]]), new Map([[k1.kid, end]]), 1)).toBe(true);
    expect(await s.keysOf(a.agent_code)).toEqual([{ ...k1, valid_to: end, row_version: 2 }, k2]);
    await expect(s.addKey(k2, new Map(), new Map(), 1)).rejects.toThrow(KeyTakenError);
    await expect(s.addKey(key(`k3-${a.id}`, `${a.agent_code}-нет`), new Map(), new Map(), 1)).rejects.toThrow("Агента нет в реестре");
  });

  it("отзыв ключа — по версии; повторный отзыв и устаревшая версия — undefined (РП23 п. 5)", async () => {
    const s = make();
    const a = record(uid());
    const k = key(`k-${a.id}`, a.agent_code);
    await s.insert(a, k);
    expect(await s.revokeKey(k.kid, 2, LATER)).toBeUndefined();
    expect(await s.revokeKey(k.kid, 1, LATER)).toEqual({ ...k, revoked_at: LATER, row_version: 2 });
    expect(await s.revokeKey(k.kid, 2, LATER)).toBeUndefined();
    expect(await s.revokeKey("нет", 1, LATER)).toBeUndefined();
  });

  it("подписка заменяется целиком; агента нет — false (РП40 п. 1)", async () => {
    const s = make();
    const a = record(uid());
    await s.insert(a, key(`k-${a.id}`, a.agent_code));
    expect(await s.subscriptionOf(a.agent_code)).toBeUndefined();
    expect(await s.setSubscription(a.agent_code, { url: "https://a.example/e", events: ["mandate.signed", "agent.suspended"] })).toBe(true);
    expect(await s.setSubscription(a.agent_code, { url: "https://b.example/e", events: [] })).toBe(true);
    expect(await s.subscriptionOf(a.agent_code)).toEqual({ url: "https://b.example/e", events: [] });
    expect(await s.setSubscription(`${a.agent_code}-нет`, { url: "https://a.example/e", events: [] })).toBe(false);
  });
});

describe.skipIf(!DATABASE_URL)("PostgreSQL: реестр агентов с двух экземпляров и ограничения схемы (РП64 п. 1–2)", () => {
  const two = (): [PgAgentRegistryStore, PgAgentRegistryStore] => {
    const d = db as TestDb;
    return [new PgAgentRegistryStore(d.pool), new PgAgentRegistryStore(d.reopen())];
  };

  it("одновременная смена статуса по одной версии — проходит ровно одна", async () => {
    const [one, other] = two();
    const a = record(uid());
    await one.insert(a, key(`k-${a.id}`, a.agent_code));
    const f = { status: "SUSPENDED", status_ground: "OUT_OF_MANDATE", status_changed_at: LATER, suspended_at: LATER } as const;
    const res = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? other : one).updateStatus(a.agent_code, 1, f)));
    expect(res.filter(Boolean)).toHaveLength(1);
    expect((await other.get(a.agent_code))?.row_version).toBe(2);
  });

  it("одновременная вставка того же идентификатора разными операторами и одновременный новый ключ — проходит один", async () => {
    const [one, other] = two();
    const id = uid();
    const ins = await Promise.allSettled(
      ["op-a", "op-b", "op-c", "op-d"].map((operator, i) =>
        (i % 2 ? other : one).insert(
          record(id, { agent_code: `nspk:agent:${id}:v${i + 1}`, version: i + 1, operator }),
          key(`k${i}-${id}`, `nspk:agent:${id}:v${i + 1}`),
        ),
      ),
    );
    expect(ins.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    for (const r of ins) if (r.status === "rejected") expect(r.reason).toBeInstanceOf(AgentCodeTakenError);

    const a = record(uid());
    const k1 = key(`k1-${a.id}`, a.agent_code);
    await one.insert(a, k1);
    const added = await Promise.all(
      Array.from({ length: 6 }, (_, i) =>
        (i % 2 ? other : one).addKey(key(`n${i}-${a.id}`, a.agent_code), new Map([[k1.kid, 1]]), new Map([[k1.kid, LATER]]), 1),
      ),
    );
    expect(added.filter(Boolean)).toHaveLength(1);
    expect(await one.keysOf(a.agent_code)).toHaveLength(2);
  });

  it("ограничения схемы: основание по статусу, класс и контур из перечня, ключ без агента", async () => {
    const d = db as TestDb;
    const s = new PgAgentRegistryStore(d.pool);
    const a = record(uid());
    await s.insert(a, key(`k-${a.id}`, a.agent_code));
    await expect(d.pool.query("UPDATE agents SET status = 'SUSPENDED' WHERE agent_code = $1", [a.agent_code])).rejects.toThrow(/agents_status_ground/);
    await expect(
      d.pool.query("UPDATE agents SET status_ground = 'WITHDRAWN', status = 'SUSPENDED' WHERE agent_code = $1", [a.agent_code]),
    ).rejects.toThrow(/agents_status_ground/);
    await expect(d.pool.query("UPDATE agents SET class = 'ROBOT' WHERE agent_code = $1", [a.agent_code])).rejects.toThrow(/check/);
    await expect(d.pool.query("UPDATE agents SET contour = 'prod' WHERE agent_code = $1", [a.agent_code])).rejects.toThrow(/check/);
    await expect(s.insert(record(uid(), { status: "EXCLUDED", status_ground: "WITHDRAWN" }), key(`kx-${uid()}`, "x"))).rejects.toThrow(
      "Первый ключ не этого агента",
    );
    await expect(
      d.pool.query(
        "INSERT INTO agent_keys (kid, agent_code, alg, public_key, valid_from, valid_to, row_version) VALUES ('kz', 'нет', 'ed25519', 'p', now(), now(), 1)",
      ),
    ).rejects.toThrow(/agent_keys_agent_code_fkey/);
  });
});
