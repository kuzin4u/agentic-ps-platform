// Режим «только BYPASS» при ready: false (PS-10 К2.3, РП43 п. 8, решение владельца 19.10.2026): неагентским — BYPASS,
// агентским — 503 без решения (у процессинга ADP_UNAVAILABLE), ПАО и П10 не регистрируются, /health — 200 с
// mode: "bypass_only" и кодами непрошедших проверок, при входе в режим — запись «тревога» (инвариант 2, РП4).
import { describe, expect, it } from "vitest";
import { AGENT_KEYS_PATH, BYPASS_RETRY_AFTER_SEC } from "../../src/participants/merchant-api.js";
import { PAO_CONFIGURATION_PATH } from "../../src/pao/configuration.js";
import { buildServer } from "../../src/server.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { setup } from "../support/state.js";

const FAILURES = [
  { check: "db.migrations", code: "STARTUP_DB_MIGRATIONS" },
  { check: "participants", code: "STARTUP_PARTICIPANTS_INVALID" },
];
const auth: CanonicalMessage = {
  op_ref: "OPKC-BYPASS-ONLY-1",
  msg_type: "AUTH_REQUEST",
  channel: "CARD",
  amount: 10_000,
  currency: "RUB",
  merchant: { id: "MER-1042" },
  instrument: { kind: "CARD_TOKEN", token_ref: "tok_card_1" },
  aoi: { indicator: true, agent_code: "nspk:agent:a:v1", mandate_id: "mnd_x" },
};
const { aoi: _aoi, ...plain } = auth;
void _aoi;

function bypassOnly() {
  const alarms: { fields: Record<string, unknown>; msg: string }[] = [];
  // Зависимости ПАО и П10 переданы — режим их всё равно не регистрирует.
  const c = setup();
  const app = buildServer({
    env: "sandbox",
    participants: { trusted: undefined as never, consent: c.consent, params: undefined as never, state: c.state },
    bypassOnly: { failures: FAILURES, alarm: (fields, msg) => alarms.push({ fields, msg }) },
  });
  return { app, alarms };
}

describe("режим «только BYPASS» (РП43 п. 8)", () => {
  it("/health — 200 с mode: bypass_only и кодами непрошедших проверок", async () => {
    const { app } = bypassOnly();
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok", env: "sandbox", mode: "bypass_only", failures: FAILURES });
  });

  it("при входе в режим — одна запись «тревога» с кодами, без текста исключений", () => {
    const { alarms } = bypassOnly();
    expect(alarms).toHaveLength(1);
    expect(alarms[0]?.fields).toEqual({ alarm: true, mode: "bypass_only", failures: FAILURES });
  });

  it("неагентская — 200 BYPASS без задержки на хранилища", async () => {
    const { app } = bypassOnly();
    const res = await app.inject({ method: "POST", url: "/adp/v1/decide", payload: plain });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ decision: "BYPASS", reason: null, decided_in_ms: 0 });
  });

  it("агентская — 503 без решения (процессинг ставит ADP_UNAVAILABLE)", async () => {
    const { app } = bypassOnly();
    const res = await app.inject({ method: "POST", url: "/adp/v1/decide", payload: auth });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({});
  });

  it("маршрутов ПАО и П10 нет — в том числе знака готовности для агента и эквайрера (РП57 п. 3)", async () => {
    const { app } = bypassOnly();
    expect((await app.inject({ method: "POST", url: "/participants/v1/mandates/mnd_x/sign", payload: {} })).statusCode).toBe(404);
    expect((await app.inject({ method: "GET", url: "/participants/v1/merchants/MER-1042/readiness" })).statusCode).toBe(404);
    expect((await app.inject({ method: "POST", url: "/participants/v1/merchants/MER-1042/readiness", payload: {} })).statusCode).toBe(404);
  });

  it("шлюза ПАО нет — любой путь /pao, в том числе с телом, 503 UPSTREAM_UNAVAILABLE по §6 с Retry-After, без пути (РП62 доп. к п. 1)", async () => {
    const { app } = bypassOnly();
    const mark = "markbypass7f3";
    const calls = [
      { method: "GET" as const, url: `/pao/v1/agent?q=${mark}` },
      { method: "GET" as const, url: `/pao/v1/merchants/${mark}/readiness` },
      { method: "GET" as const, url: "/pao" },
      { method: "POST" as const, url: `/pao/v1/mandates?q=${mark}`, headers: { "content-type": "application/json" }, payload: "{" },
      { method: "POST" as const, url: `/pao/v1/mandates`, headers: { "content-type": "application/json" }, payload: "x".repeat(70_000) },
    ];
    for (const c of calls) {
      const res = await app.inject(c);
      expect(res.statusCode).toBe(503);
      expect(res.headers["retry-after"]).toBe(String(BYPASS_RETRY_AFTER_SEC));
      expect(res.json()).toStrictEqual({ code: "UPSTREAM_UNAVAILABLE", message: expect.any(String), retry: "same_key" });
      expect(res.body).not.toContain(mark);
    }
  });

  it("API для продавцов — 503 UPSTREAM_UNAVAILABLE с Retry-After и без Cache-Control, а не 404 (уточнение РП56, № 42; знак — РП57 п. 3)", async () => {
    const { app } = bypassOnly();
    for (const url of [AGENT_KEYS_PATH, "/merchants/v1/agents/nspk:agent:a:v1", "/merchants/v1/merchants/MER-1042/readiness"]) {
      const res = await app.inject({ method: "GET", url });
      expect(res.statusCode).toBe(503);
      expect(res.headers["retry-after"]).toBe(String(BYPASS_RETRY_AFTER_SEC));
      expect(res.headers["cache-control"]).toBeUndefined();
      expect(res.json()).toEqual({ code: "UPSTREAM_UNAVAILABLE" });
    }
  });

  it("обнаружение ПАО — 503 UPSTREAM_UNAVAILABLE по ПАО §6 с Retry-After, а не 404 (РП60 п. 12)", async () => {
    const { app } = bypassOnly();
    const res = await app.inject({ method: "GET", url: PAO_CONFIGURATION_PATH });
    expect(res.statusCode).toBe(503);
    expect(res.headers["retry-after"]).toBe(String(BYPASS_RETRY_AFTER_SEC));
    expect(res.json()).toEqual({ code: "UPSTREAM_UNAVAILABLE", message: expect.any(String), retry: "same_key" });
  });

  it("в обычном режиме /health — как прежде, без mode", async () => {
    const res = await buildServer({ env: "dev" }).inject({ method: "GET", url: "/health" });
    expect(res.json()).toEqual({ status: "ok", env: "dev" });
  });
});
