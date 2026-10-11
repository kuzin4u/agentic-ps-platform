// Маршруты ПАО: ответ на сбой источника по HTTP — 503 UPSTREAM_UNAVAILABLE с Retry-After (ПАО §2, §6; РП24; аудит PS-04 №2).
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { PaoRequestVerifier } from "../../src/pao/index.js";
import { AgentKeys, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { newAgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

describe("ПАО по HTTP: сбой источника", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
  });

  const serverWith = (retryAfter: number): FastifyInstance => {
    const params = { ...loadParams(), unavailable_retry_after_sec: retryAfter };
    const keys = new AgentKeys(new InMemoryAgentRegistryStore(), { keys: params });
    const verifier = new PaoRequestVerifier(
      {
        getAgent: () => {
          throw new Error("db down: secret-host:5432");
        },
        lookupKey: () => undefined,
      },
      { skewSec: params.signature_skew_sec },
    );
    return buildServer({ env: "sandbox", pao: { verifier, keys, params } });
  };

  it("503 UPSTREAM_UNAVAILABLE, Retry-After из параметров, тело ПАО §6 без текста исключения", async () => {
    app = serverWith(1);
    const res = await signedInject(app, newAgentSide(), "nspk:agent:buyref-01:v3");
    expect(res.statusCode).toBe(503);
    expect(res.headers["retry-after"]).toBe("1");
    expect(res.json()).toEqual({ code: "UPSTREAM_UNAVAILABLE", message: "Компонент Платформы недоступен", retry: "same_key" });
    expect(res.body).not.toContain("secret-host");
  });

  it.each([0, 30])("Retry-After = %i — как в конфигурации", async (v) => {
    app = serverWith(v);
    const res = await signedInject(app, newAgentSide(), "nspk:agent:buyref-01:v3");
    expect(res.headers["retry-after"]).toBe(String(v));
  });

  it("у отказов 401 Retry-After нет", async () => {
    const params = loadParams();
    const store = new InMemoryAgentRegistryStore();
    const keys = new AgentKeys(store, { keys: params });
    const verifier = new PaoRequestVerifier(
      { getAgent: () => undefined, lookupKey: () => undefined },
      { skewSec: params.signature_skew_sec },
    );
    app = buildServer({ env: "sandbox", pao: { verifier, keys, params } });
    const res = await signedInject(app, newAgentSide(), "nspk:agent:buyref-01:v3");
    expect(res.statusCode).toBe(401);
    expect(res.headers["retry-after"]).toBeUndefined();
  });
});
