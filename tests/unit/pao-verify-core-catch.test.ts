// Повторный аудит PS-04 №3: если agentic-core сам перехватит исключение lookupKey и вернёт отказ подписи,
// сбой источника всё равно — UPSTREAM_UNAVAILABLE, а не SIGNATURE_INVALID (РП23 п. 6, инвариант 3).
import { describe, expect, it, vi } from "vitest";

vi.mock("@kuzin4u/agentic-core", async (orig) => {
  const core = await orig<typeof import("@kuzin4u/agentic-core")>();
  return {
    ...core,
    verifyRequestAsync: (async (req, lookupKey, opts) => {
      try {
        return await core.verifyRequestAsync(req, lookupKey, opts);
      } catch {
        return { ok: false, code: "SIGNATURE_INVALID" };
      }
    }) as typeof core.verifyRequestAsync,
  };
});

const { newEd25519Signer, signRequest } = await import("@kuzin4u/agentic-core");
const { PaoRequestVerifier } = await import("../../src/pao/verify.js");

describe("core перехватывает исключение поиска ключа", () => {
  it("сбой lookupKey или хранилища nonce — UPSTREAM_UNAVAILABLE с причиной (РП30 п. 1)", async () => {
    const now = new Date("2026-10-11T12:00:00Z");
    const code = "nspk:agent:buyref-01:v3";
    const { signer } = newEd25519Signer("k");
    const req = signRequest(
      {
        method: "GET",
        path: "/pao/v1/agent",
        query: "",
        headers: { "x-agent-code": code, "x-timestamp": now.toISOString(), "x-nonce": "n-1" },
        body: "",
      },
      signer,
    );
    const seen: string[] = [];
    const v = new PaoRequestVerifier(
      {
        getAgent: () => ({ agent_code: code, status: "ACTIVE" }) as never,
        lookupKey: () => {
          throw new Error("db down");
        },
      },
      { skewSec: 300, now: () => now, nonces: { seen: async (n) => (seen.push(n), false), purge: async () => 0 } },
    );
    const r = await v.verify({ method: "GET", path: req.path, query: "", headers: req.headers, body: "" });
    expect(r).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
    expect(seen).toEqual([]);

  });

  it("ключ найден, подпись верна, хранилище nonce недоступно — UPSTREAM_UNAVAILABLE с причиной (РП30 п. 1)", async () => {
    const now = new Date("2026-10-11T12:00:00Z");
    const code = "nspk:agent:buyref-01:v3";
    const { signer, publicKey } = newEd25519Signer("k");
    const req = signRequest(
      {
        method: "GET",
        path: "/pao/v1/agent",
        query: "",
        headers: { "x-agent-code": code, "x-timestamp": now.toISOString(), "x-nonce": "n-1" },
        body: "",
      },
      signer,
    );
    const v = new PaoRequestVerifier(
      {
        getAgent: () => ({ agent_code: code, status: "ACTIVE" }) as never,
        lookupKey: () => ({ alg: "ed25519", publicKey, status: "ACTIVE" }),
      },
      {
        skewSec: 300,
        now: () => now,
        nonces: {
          seen: async () => {
            throw new Error("nonce db down");
          },
          purge: async () => 0,
        },
      },
    );
    const r = await v.verify({ method: "GET", path: req.path, query: "", headers: req.headers, body: "" });
    expect(r).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
    expect((r as { cause?: Error }).cause?.message).toBe("nonce db down");
  });
});
