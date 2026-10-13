// РП22 п. 1–2: каталог ключей агентов — JWKS; kid = Key.kid ПАО; только действующие ключи агентов ACTIVE.
import { describe, expect, it } from "vitest";
import { createStand } from "../../src/stand/index.js";
import { jwkThumbprint } from "../../src/registry/keys.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";

const A = "nspk:agent:jwks-a:v1";
const B = "nspk:agent:jwks-b:v1";
const DAY = 86_400_000;

function setup() {
  const s = createStand();
  const t0 = new Date("2026-10-13T10:00:00Z");
  s.setClock(t0);
  const a = newAgentSide();
  const b = newAgentSide();
  expect(s.admit(buyerApplication(A, a), "op-a").admitted).toBe(true);
  expect(s.admit(buyerApplication(B, b), "op-b").admitted).toBe(true);
  return { s, a, b, t0 };
}

describe("РП22 п. 1: формат JWK", () => {
  it("члены RFC 8037 и частные agent_code, nbf, exp; kid — отпечаток RFC 7638 из {crv, kty, x} и равен Key.kid ПАО", () => {
    const { s, a } = setup();
    const jwk = s.keys.jwks().keys.find((k) => k.agent_code === A);
    expect(jwk).toBeDefined();
    expect(Object.keys(jwk!).sort()).toEqual(["agent_code", "alg", "crv", "exp", "kid", "kty", "nbf", "use", "x"]);
    expect(jwk).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", agent_code: A });
    expect(Buffer.from(jwk!.x, "base64url")).toHaveLength(32);
    expect(jwk!.kid).toBe(jwkThumbprint({ crv: jwk!.crv, kty: jwk!.kty, x: jwk!.x }));
    expect(jwk!.kid).toBe(a.kid);
    const pao = s.keys.list(A)[0]!;
    expect(jwk!.kid).toBe(pao.kid);
    expect(jwk!.nbf).toBe(Math.floor(Date.parse(pao.valid_from as string) / 1000));
    expect(jwk!.exp).toBe(Math.floor(Date.parse(pao.valid_to as string) / 1000));
  });

  it("закрытой части ключа (d) в каталоге нет", () => {
    const { s } = setup();
    for (const k of s.keys.jwks().keys) expect(k).not.toHaveProperty("d");
  });
});

describe("РП22 п. 2: только действующие ключи агентов ACTIVE", () => {
  it("отозванный ключ удаляется, остальные остаются", () => {
    const { s, a } = setup();
    s.keys.revoke(A, a.kid);
    const kids = s.keys.jwks().keys.map((k) => k.agent_code);
    expect(kids).not.toContain(A);
    expect(kids).toContain(B);
  });

  it("истёкший ключ удаляется", () => {
    const { s, t0 } = setup();
    s.setClock(new Date(t0.getTime() + (s.params.key_ttl_days + 1) * DAY));
    expect(s.keys.jwks().keys).toEqual([]);
  });

  it("ключи приостановленного и исключённого агента удаляются; после снятия приостановления — возвращаются", () => {
    const { s } = setup();
    s.registry.changeStatus(A, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    s.registry.changeStatus(B, { to: "EXCLUDED", ground: "WITHDRAWN" });
    expect(s.keys.jwks().keys).toEqual([]);
    s.registry.changeStatus(A, { to: "ACTIVE" });
    expect(s.keys.jwks().keys.map((k) => k.agent_code)).toEqual([A]);
  });

  it("при ротации в каталоге оба ключа на время перекрытия, после — только новый", () => {
    const { s, t0 } = setup();
    const next = newAgentSide();
    s.keys.register(A, { alg: "ed25519", public_key: next.publicKey });
    expect(s.keys.jwks().keys.filter((k) => k.agent_code === A)).toHaveLength(2);
    s.setClock(new Date(t0.getTime() + (s.params.key_overlap_days + 1) * DAY));
    expect(s.keys.jwks().keys.filter((k) => k.agent_code === A).map((k) => k.kid)).toEqual([next.kid]);
  });
});
