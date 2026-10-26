// Nonce шлюза ПАО на PostgreSQL (РП30 п. 1–2, 7; Ш3а; «Условие CO-2» STATUS). PG-тесты — только при DATABASE_URL:
// локально пропуск, в CI их выполнение сторожит tests/unit/pg.test.ts.
import { signRequest, type HttpLike, type SqlClient } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import pg from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  PAO_NONCE_SCOPE,
  PaoRequestVerifier,
  nonceValue,
  paoIdempotency,
  paoNonceStore,
  paoPoolConfig,
  requireDatabaseUrl,
  type PaoAuthResult,
  type PaoRequest,
} from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";
import { barrierClient } from "../support/pg-barrier.js";
import { signedInject } from "../support/signed-inject.js";
import { memoryConsent } from "../support/consent.js";

const params = loadParams();
const SKEW = params.signature_skew_sec;
const A = "nspk:agent:buyref-01:v3";
const B = "nspk:agent:other-01:v1";

/** Реестр в памяти с допущенными A и B; «экземпляр шлюза» — проверяющий на своём пуле той же базы. */
async function registry() {
  const store = new InMemoryAgentRegistryStore();
  const reg = new AgentRegistry(store, { keys: params });
  const keys = new AgentKeys(store, { keys: params });
  const sides = new Map<string, AgentSide>();
  for (const code of [A, B]) {
    const side = newAgentSide();
    expect((await reg.admit(buyerApplication(code, side), { contour: "sandbox", operator: "op" })).admitted).toBe(true);
    sides.set(code, side);
  }
  const gateway = (client: SqlClient, now: () => Date = () => new Date()) =>
    new PaoRequestVerifier(
      { getAgent: (c) => reg.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: SKEW, now, nonces: paoNonceStore({ client, skewSec: SKEW, now: () => now().getTime() }) },
    );
  return { reg, keys, sides, gateway };
}

function signed(side: AgentSide, agent_code: string, nonce: string, ts: Date = new Date()): PaoRequest {
  const req: HttpLike = {
    method: "GET",
    path: "/pao/v1/agent",
    query: "",
    headers: { "x-agent-code": agent_code, "x-timestamp": ts.toISOString(), "x-nonce": nonce },
    body: "",
  };
  const s = signRequest(req, side.signer);
  return { method: s.method, path: s.path, query: s.query ?? "", headers: s.headers, body: s.body ?? "" };
}

const code = (r: PaoAuthResult): string => (r.ok ? "OK" : r.code);
let seq = 0;
const fresh = (): string => `n-${process.pid}-${++seq}`;

describe.skipIf(!DATABASE_URL)("nonce шлюза ПАО на PostgreSQL (РП30, Ш3а)", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("nonce");
  });
  afterAll(async () => {
    await db?.close();
  });

  const rows = async (value: string): Promise<number> =>
    (
      await db.pool.query<{ n: number }>("SELECT count(*)::int AS n FROM core_nonces WHERE scope = $1 AND nonce = $2", [
        PAO_NONCE_SCOPE,
        value,
      ])
    ).rows[0]!.n;

  it("повтор nonce после «перезапуска» (новый экземпляр шлюза на той же базе) — SIGNATURE_INVALID", async () => {
    const r = await registry();
    const n = fresh();
    const req = signed(r.sides.get(A)!, A, n);
    expect(code(await r.gateway(db.pool).verify(req))).toBe("OK");
    expect(await rows(nonceValue(A, n))).toBe(1);
    const restarted = r.gateway(db.reopen());
    expect(code(await restarted.verify(req))).toBe("SIGNATURE_INVALID");
  });

  it("тот же x-nonce у другого агента — принят: одна область pao, агент различается значением", async () => {
    const r = await registry();
    const n = fresh();
    const g = r.gateway(db.pool);
    expect(code(await g.verify(signed(r.sides.get(A)!, A, n)))).toBe("OK");
    expect(code(await g.verify(signed(r.sides.get(B)!, B, n)))).toBe("OK");
    expect(await rows(nonceValue(A, n))).toBe(1);
    expect(await rows(nonceValue(B, n))).toBe(1);
  });

  it("из 20 одновременных одинаковых обращений на двух экземплярах принято одно", async () => {
    const r = await registry();
    const req = signed(r.sides.get(A)!, A, fresh());
    const g1 = r.gateway(db.pool);
    const g2 = r.gateway(db.reopen());
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? g1 : g2).verify(req)));
    expect(results.map(code).filter((c) => c === "OK")).toHaveLength(1);
    expect(results.map(code).filter((c) => c === "SIGNATURE_INVALID")).toHaveLength(19);
  });

  // Тест выше идёт через пул: первый вызов успевает и проверку, и запись, поэтому поломку «проверка и захват двумя
  // командами» он не ловит (№ 21 ядра). Через барьер первые ответы базы — по одному на обращение — приходят вместе.
  it("10 одновременных через барьер ответов базы — принято ровно одно (проверка и захват — одна команда)", async () => {
    const r = await registry();
    const req = signed(r.sides.get(A)!, A, fresh());
    const n = 10;
    const b = barrierClient(db.pool, n);
    const g = r.gateway(b.client);
    const results = await Promise.all(Array.from({ length: n }, () => g.verify(req)));
    b.close();
    expect(b.left()).toBe(0);
    expect(results.map(code).filter((c) => c === "OK")).toHaveLength(1);
    expect(results.map(code).filter((c) => c === "SIGNATURE_INVALID")).toHaveLength(n - 1);
  });

  it("неподписанное, с чужой подписью или просроченное обращение nonce не записывает", async () => {
    const r = await registry();
    const side = r.sides.get(A)!;
    const n = fresh();
    const g = r.gateway(db.pool);
    const good = signed(side, A, n);
    const noSig = { ...good, headers: { ...good.headers, signature: "sig1=:AAAA:" } };
    const foreign = signed(r.sides.get(B)!, A, n);
    const expired = signed(side, A, n, new Date(Date.now() - (SKEW + 5) * 1000));
    for (const bad of [noSig, foreign, expired]) expect(code(await g.verify(bad))).toBe("SIGNATURE_INVALID");
    expect(await rows(nonceValue(A, n))).toBe(0);
    // Отозванный ключ — AGENT_KEY_REVOKED до подписи и nonce (РП23 п. 6.2): nonce не пишется.
    const revoked = r.sides.get(B)!;
    const m = fresh();
    await r.keys.revoke(B, revoked.kid);
    expect(code(await g.verify(signed(revoked, B, m)))).toBe("AGENT_KEY_REVOKED");
    expect(await rows(nonceValue(B, m))).toBe(0);
    expect(code(await g.verify(good))).toBe("OK");
    expect(await rows(nonceValue(A, n))).toBe(1);
  });

  it("x-nonce 8 000 знаков — принят и записан хэшем, повтор — SIGNATURE_INVALID (РП62 п. 11; аудит К2.3 № 8)", async () => {
    // Сырой x-nonce длиннее ≈ 2,7 КБ не помещался в индекс первичного ключа core_nonces — PostgreSQL отвечал ошибкой, 503.
    const r = await registry();
    const n = "n".repeat(7_990) + fresh();
    const g = r.gateway(db.pool);
    const req = signed(r.sides.get(A)!, A, n);
    expect(code(await g.verify(req))).toBe("OK");
    expect(await rows(nonceValue(A, n))).toBe(1);
    expect(code(await g.verify(req))).toBe("SIGNATURE_INVALID");
  });

  it("пустой x-nonce — SIGNATURE_INVALID, в базу не попадает (приставка агента не делает его непустым)", async () => {
    const r = await registry();
    expect(code(await r.gateway(db.pool).verify(signed(r.sides.get(A)!, A, "")))).toBe("SIGNATURE_INVALID");
    expect(await rows(nonceValue(A, ""))).toBe(0);
  });

  it("срок хранения — 2 × signature_skew_sec: purge на границе не удаляет, после — удаляет", async () => {
    let t = Date.now();
    const store = paoNonceStore({ client: db.pool, skewSec: SKEW, now: () => t });
    const v = nonceValue(A, fresh());
    expect(await store.seen(v)).toBe(false);
    t += 2 * SKEW * 1000;
    await store.purge();
    expect(await rows(v)).toBe(1);
    expect(await store.seen(v)).toBe(true);
    t += 1;
    await store.purge();
    expect(await rows(v)).toBe(0);
  });

  it("зависшая база (строка nonce под чужой блокировкой) — UPSTREAM_UNAVAILABLE по таймауту запроса, не ожидание", async () => {
    const r = await registry();
    const n = fresh();
    const holder = await db.pool.connect();
    try {
      await holder.query("BEGIN");
      await holder.query("INSERT INTO core_nonces (scope, nonce, at) VALUES ($1, $2, 0)", [PAO_NONCE_SCOPE, nonceValue(A, n)]);
      const slowDb = new pg.Pool({ ...paoPoolConfig(DATABASE_URL!, 300), options: db.searchPathOption });
      try {
        const started = Date.now();
        const res = await r.gateway(slowDb).verify(signed(r.sides.get(A)!, A, n));
        expect(res).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
        expect(Date.now() - started).toBeLessThan(5000);
      } finally {
        await slowDb.end();
      }
    } finally {
      await holder.query("ROLLBACK");
      holder.release();
    }
  });

  it("сбой базы — UPSTREAM_UNAVAILABLE с причиной, проверка не пропускает обращение", async () => {
    const r = await registry();
    const down = db.reopen();
    await down.end();
    const res = await r.gateway(down).verify(signed(r.sides.get(A)!, A, fresh()));
    expect(res).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
    expect((res as { cause?: unknown }).cause).toBeDefined();
  });
});

describe("сбой хранилища nonce по HTTP — 503 с Retry-After (РП30 п. 1, РП24)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
  });

  it("503 UPSTREAM_UNAVAILABLE, Retry-After из параметров, тело без текста исключения", async () => {
    const r = await registry();
    const failing = {
      query: async (): Promise<never> => {
        throw new Error("connect ECONNREFUSED secret-db:5432");
      },
    };
    app = buildServer({ env: "sandbox", pao: { verifier: r.gateway(failing), keys: r.keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() } });
    const res = await signedInject(app, r.sides.get(A)!, A);
    expect(res.statusCode).toBe(503);
    expect(res.headers["retry-after"]).toBe(String(params.unavailable_retry_after_sec));
    expect(res.json()).toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retry: "same_key" });
    expect(res.body).not.toContain("secret-db");
  });
});

describe("без базы запускается только dev (РП30 п. 6)", () => {
  it("sandbox без DATABASE_URL — отказ запуска; dev — память; с адресом — адрес", () => {
    expect(() => requireDatabaseUrl("sandbox", undefined)).toThrow(/sandbox без DATABASE_URL не запускается/);
    expect(() => requireDatabaseUrl("sandbox", "")).toThrow(/не запускается/);
    expect(requireDatabaseUrl("dev", undefined)).toBeUndefined();
    expect(requireDatabaseUrl("sandbox", "postgres://h/db")).toBe("postgres://h/db");
  });
});
