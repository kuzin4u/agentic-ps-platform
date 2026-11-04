// Тело в /pao — байтами (#102, ядро v0.12.0 К22, РП62 п. 9; решение владельца 04.11, PR #103): подпись по присланным
// байтам → второй слой лимита → строгое UTF-8 (BOM не снимается) → 400 REQUEST_INVALID. Тело с верной подписью тратит
// квоту агента (РП63 п. 1). Поле note в теле регистрации ключа разбор игнорирует (keyRegistrationBody): тело с ним —
// верное, если декодировано без подмены байтов.
import { randomUUID } from "node:crypto";
import { signRequest } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { PaoRequestVerifier, paoIdempotency } from "../../src/pao/index.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import type { AgentRecord } from "../../src/registry/model.js";
import { buildServer } from "../../src/server.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { memoryConsent } from "../support/consent.js";
import { signedInject } from "../support/signed-inject.js";

const A = "nspk:agent:buyref-01:v3";
const PATH = "/pao/v1/agent/keys";
const NOT_UTF8 = "тело не UTF-8";

/** Тело регистрации ключа с полем note из сырых байтов. */
const keyBytes = (note: Buffer, prefix: Buffer = Buffer.alloc(0)): Buffer =>
  Buffer.concat([
    prefix,
    Buffer.from(`{"alg":"ed25519","public_key":"${newAgentSide().publicKey}","note":"`, "utf8"),
    note,
    Buffer.from(`"}`, "utf8"),
  ]);

describe("тело /pao байтами: подпись по байтам, затем строгое UTF-8 (#102, РП62 п. 9)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  const platform = async (opts: { status?: AgentRecord["status"]; params?: Record<string, number> } = {}) => {
    const params = { ...loadParams(), ...opts.params };
    const store = new InMemoryAgentRegistryStore();
    const registry = new AgentRegistry(store, { keys: params });
    const keys = new AgentKeys(store, { keys: params });
    const a = newAgentSide();
    expect((await registry.admit(buyerApplication(A, a), { contour: "sandbox", operator: "op" })).admitted).toBe(true);
    const getAgent = async (c: string) => {
      const r = await registry.get(c);
      return r && opts.status ? { ...r, status: opts.status } : r;
    };
    const verifier = new PaoRequestVerifier(
      { getAgent, lookupKey: (c, kid) => keys.lookup(c, kid) },
      { skewSec: params.signature_skew_sec },
    );
    const lines: string[] = [];
    app = buildServer({
      env: "sandbox",
      logger: { level: "info", stream: { write: (l: string) => void lines.push(l) } },
      pao: { verifier, keys, idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }), params, consent: memoryConsent() },
    });
    return { app, a, lines };
  };

  /** POST регистрации ключа: отправляются bytes, подписываются signed (по умолчанию — те же байты). */
  const post = (target: FastifyInstance, side: AgentSide, bytes: Buffer, signed: Buffer | string = bytes) => {
    const headers = {
      "content-type": "application/json",
      "idempotency-key": randomUUID(),
      "x-agent-code": A,
      "x-timestamp": new Date().toISOString().slice(0, 19) + "Z",
      "x-nonce": randomUUID(),
    };
    const s = signRequest({ method: "POST", path: PATH, query: "", headers, body: signed }, side.signer);
    return target.inject({ method: "POST", url: PATH, headers: s.headers, payload: bytes });
  };
  const notUtf8Logged = (lines: string[]) => lines.some((l) => l.includes(NOT_UTF8));

  it("(а) тело не UTF-8 с верной подписью → 400 REQUEST_INVALID, запись «тело не UTF-8» с кодом агента, без тела", async () => {
    const { app, a, lines } = await platform();
    const res = await post(app, a, keyBytes(Buffer.from([0x61, 0xff, 0x62])));
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ code: "REQUEST_INVALID", message: expect.any(String), retry: "after_fix" });
    const line = lines.find((l) => l.includes(NOT_UTF8));
    expect(line, "запись об отказе").toBeDefined();
    expect(JSON.parse(line as string)).toMatchObject({ agent_code: A });
    expect(line).not.toContain("public_key");
  });

  it("(б) подпись не по присланным байтам (по их строке с заменой) → 401 SIGNATURE_INVALID, до декодирования", async () => {
    const { app, a, lines } = await platform();
    const bytes = keyBytes(Buffer.from([0x61, 0xff, 0x62]));
    // Подписана строка, которую дал бы String(buffer): байт 0xff заменён на U+FFFD — digest от неё не совпадает с байтами.
    const res = await post(app, a, bytes, bytes.toString("utf8"));
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ code: "SIGNATURE_INVALID" });
    expect(notUtf8Logged(lines)).toBe(false);
  });

  it("(в) тело с BOM — BOM не снимается: 400 REQUEST_INVALID разбором тела, не декодированием; без BOM — 201", async () => {
    const { app, a, lines } = await platform();
    const bom = await post(app, a, keyBytes(Buffer.from("x", "utf8"), Buffer.from([0xef, 0xbb, 0xbf])));
    expect(bom.statusCode).toBe(400);
    expect(bom.json()).toEqual({ code: "REQUEST_INVALID", message: expect.any(String), retry: "after_fix" });
    // Причина — разбор JSON (BOM — допустимый UTF-8), а не строгий декодер (Р-1138).
    expect(notUtf8Logged(lines)).toBe(false);
    expect((await post(app, a, keyBytes(Buffer.from("x", "utf8")))).statusCode).toBe(201);
  });

  it("(г) многобайтовый UTF-8 (кириллица) проходит: digest — от байтов, тело — та же строка", async () => {
    const { app, a, lines } = await platform();
    const res = await post(app, a, keyBytes(Buffer.from("ключ — проверка", "utf8")));
    expect(res.statusCode).toBe(201);
    expect(notUtf8Logged(lines)).toBe(false);
  });

  it("(д) приостановленный агент с телом не UTF-8 → 403 AGENT_SUSPENDED: статус — до декодирования", async () => {
    const { app, a, lines } = await platform({ status: "SUSPENDED" });
    const res = await post(app, a, keyBytes(Buffer.from([0xc3, 0x28])));
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: "AGENT_SUSPENDED" });
    expect(notUtf8Logged(lines)).toBe(false);
  });

  it("(е) тело не UTF-8 с верной подписью тратит квоту второго слоя: после двух таких — 429 (РП63 п. 1)", async () => {
    // L1 = 4 в минуту — 2 за окно 30 с, первый слой щедрый (как pao-rate-limit.test.ts).
    const { app, a } = await platform({
      params: {
        pao_rate_limit_per_30s: 1000,
        pao_agent_rate_limit_per_min_l1: 4,
        pao_agent_rate_limit_per_min_l2: 6,
        pao_agent_rate_limit_per_min_l3: 8,
      },
    });
    for (let i = 0; i < 2; i++) expect((await post(app, a, keyBytes(Buffer.from([0xff])))).statusCode).toBe(400);
    const res = await signedInject(app, a, A);
    expect(res.statusCode).toBe(429);
    expect(res.json()).toMatchObject({ code: "RATE_LIMITED" });
  });
});
