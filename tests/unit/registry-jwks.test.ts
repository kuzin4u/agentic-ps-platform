// РП22 п. 1–2: каталог ключей агентов — JWKS; kid = Key.kid ПАО; только действующие ключи агентов ACTIVE.
import { describe, expect, it } from "vitest";
import type { TxSqlPool } from "../../src/consent/store.js";
import { createStand } from "../../src/stand/index.js";
import { AgentKeys, PgAgentRegistryStore } from "../../src/registry/index.js";
import { jwkThumbprint } from "../../src/registry/keys.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";

const A = "nspk:agent:jwks-a:v1";
const B = "nspk:agent:jwks-b:v1";
const DAY = 86_400_000;

async function setup() {
  const s = createStand();
  const t0 = new Date("2026-10-13T10:00:00Z");
  s.setClock(t0);
  const a = newAgentSide();
  const b = newAgentSide();
  expect((await s.admit(buyerApplication(A, a), "op-a")).admitted).toBe(true);
  expect((await s.admit(buyerApplication(B, b), "op-b")).admitted).toBe(true);
  return { s, a, b, t0 };
}

describe("РП22 п. 1: формат JWK", () => {
  it("члены RFC 8037 и частные agent_code, nbf, exp; kid — отпечаток RFC 7638 из {crv, kty, x} и равен Key.kid ПАО", async () => {
    const { s, a } = await setup();
    const jwk = (await s.keys.jwks("sandbox")).keys.find((k) => k.agent_code === A);
    expect(jwk).toBeDefined();
    expect(Object.keys(jwk!).sort()).toEqual(["agent_code", "alg", "crv", "exp", "kid", "kty", "nbf", "use", "x"]);
    expect(jwk).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", agent_code: A });
    expect(Buffer.from(jwk!.x, "base64url")).toHaveLength(32);
    expect(jwk!.kid).toBe(jwkThumbprint({ crv: jwk!.crv, kty: jwk!.kty, x: jwk!.x }));
    expect(jwk!.kid).toBe(a.kid);
    const pao = (await s.keys.list(A))[0]!;
    expect(jwk!.kid).toBe(pao.kid);
    expect(jwk!.nbf).toBe(Math.floor(Date.parse(pao.valid_from as string) / 1000));
    expect(jwk!.exp).toBe(Math.floor(Date.parse(pao.valid_to as string) / 1000));
  });

  it("закрытой части ключа (d) в каталоге нет", async () => {
    const { s } = await setup();
    for (const k of (await s.keys.jwks("sandbox")).keys) expect(k).not.toHaveProperty("d");
  });
});

describe("РП22 п. 2: только действующие ключи агентов ACTIVE", () => {
  it("отозванный ключ удаляется, остальные остаются", async () => {
    const { s, a } = await setup();
    await s.keys.revoke(A, a.kid);
    const kids = (await s.keys.jwks("sandbox")).keys.map((k) => k.agent_code);
    expect(kids).not.toContain(A);
    expect(kids).toContain(B);
  });

  it("истёкший ключ удаляется", async () => {
    const { s, t0 } = await setup();
    s.setClock(new Date(t0.getTime() + (s.params.key_ttl_days + 1) * DAY));
    expect((await s.keys.jwks("sandbox")).keys).toEqual([]);
  });

  it("ключи приостановленного и исключённого агента удаляются; после снятия приостановления — возвращаются", async () => {
    const { s } = await setup();
    await s.registry.changeStatus(A, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    await s.registry.changeStatus(B, { to: "EXCLUDED", ground: "WITHDRAWN" });
    expect((await s.keys.jwks("sandbox")).keys).toEqual([]);
    await s.registry.changeStatus(A, { to: "ACTIVE" });
    expect((await s.keys.jwks("sandbox")).keys.map((k) => k.agent_code)).toEqual([A]);
  });

  it("при ротации в каталоге оба ключа на время перекрытия, после — только новый", async () => {
    const { s, t0 } = await setup();
    const next = newAgentSide();
    await s.keys.register(A, { alg: "ed25519", public_key: next.publicKey });
    expect((await s.keys.jwks("sandbox")).keys.filter((k) => k.agent_code === A)).toHaveLength(2);
    s.setClock(new Date(t0.getTime() + (s.params.key_overlap_days + 1) * DAY));
    expect((await s.keys.jwks("sandbox")).keys.filter((k) => k.agent_code === A).map((k) => k.kid)).toEqual([next.kid]);
  });
});

describe("каталог на PostgreSQL — одним запросом (КТ1 PS-05в ч. 2а № 10)", () => {
  it("jwks — одно обращение к базе вместо 2N + 1, ключи из ответа запроса", async () => {
    const queries: string[] = [];
    const row = { kid: "k1", agent_code: A, alg: "ed25519", public_key: "pk", valid_from: new Date("2026-10-01T00:00:00Z"), valid_to: new Date("2027-01-01T00:00:00Z"), revoked_at: null, row_version: "1" };
    const pool = {
      query: async (text: string) => {
        queries.push(text);
        return { rows: [row, { ...row, kid: "k2", agent_code: B }] };
      },
      connect: async () => {
        throw new Error("транзакция каталогу не нужна");
      },
    } as unknown as TxSqlPool;
    const keys = new AgentKeys(new PgAgentRegistryStore(pool), { keys: loadParams(), now: () => new Date("2026-10-27T00:00:00Z") });
    // Ключи не Ed25519 (pk не SPKI) каталог отбрасывает — здесь важно число обращений, а не JWK.
    await keys.jwks("sandbox");
    expect(queries).toHaveLength(1);
    expect(queries[0]).toMatch(/FROM agent_keys k JOIN agents a/);
  });
});
