// П5 выдача реквизита (РП47 п. 1–5): токен на CART, криптограмма на заказ, повтор по order_ref, коды отказов.
import { describe, expect, it, vi } from "vitest";
import {
  Credentials,
  MemoryCredentialStore,
  P5_UPSTREAM_TIMEOUT_MS,
  sha256Hex,
  type CredentialMandate,
  type CredentialStore,
} from "../../src/credentials/index.js";
import { createTokenServiceEmulator } from "../../src/env/tsp/index.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { PAO_HANDLER_BUDGET_MS } from "../../src/pao/idempotency.js";
import type { CredentialRequest, Mandate } from "../../src/shared/pao.js";

const AGENT = "nspk:agent:buyref-01:v1";
const CART = "mnd_00000000-0000-8000-8000-00000000c001";
const T0 = Date.parse("2026-10-20T10:00:00Z");
const TTL = 900;

function cart(over: Partial<Mandate> = {}): Mandate {
  return {
    id: CART,
    type: "CART",
    parent_id: "mnd_00000000-0000-8000-8000-00000000a001",
    subject: "s",
    amount_limit: 189_000,
    currency: "RUB",
    valid_to: "2026-10-21T10:00:00Z",
    merchant_scope: ["MER-1042"],
    principal_ref: "pr_alpha",
    mode: "IMMEDIATE",
    agent_code: AGENT,
    status: "ACTIVE",
    ...over,
  } as Mandate;
}

const req = (over: Partial<CredentialRequest> = {}): CredentialRequest => ({
  mandate_id: CART,
  order_ref: "ORD-a",
  merchant_id: "MER-1042",
  amount_max: 150_000,
  currency: "RUB",
  kind: "CARD",
  ...over,
});

function setup(opts: { mandate?: Mandate; read?: Partial<CredentialMandate> | null; store?: CredentialStore; tspDown?: boolean } = {}) {
  const issuer = createIssuerEmulator();
  const tsp = createTokenServiceEmulator();
  const store = opts.store ?? new MemoryCredentialStore();
  let now = T0;
  const read: CredentialMandate | undefined =
    opts.read === null
      ? undefined
      : {
          mandate: opts.mandate ?? cart(),
          client: { participant_code: issuer.participant_code, principal_ref: "pr_alpha" },
          token_consent: true,
          ...opts.read,
        };
  const c = new Credentials({
    mandates: { get: async (id, code) => (id === CART && code === AGENT ? read : undefined) },
    store,
    tsp: opts.tspDown
      ? { issueToken: () => Promise.reject(new Error("down")), cryptogram: () => Promise.reject(new Error("down")) }
      : tsp,
    funding: issuer,
    params: { cryptogram_ttl_sec: TTL },
    now: () => new Date(now),
  });
  return { c, tsp, store, setNow: (t: number) => (now = t) };
}

describe("П5 выдача реквизита (РП47)", () => {
  it("ПС05: реквизит по CART — токен с доменом CART, криптограмма HMAC, valid_to = сейчас + TTL, aoi из записи", async () => {
    const { c, tsp, store } = setup();
    const r = await c.issue(AGENT, req());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const { credential } = r;
    expect(credential.kind).toBe("CARD");
    expect(credential.status).toBe("ISSUED");
    expect(credential.aoi).toEqual({ indicator: true, agent_code: AGENT, mandate_id: CART });
    expect(credential.payload.valid_to).toBe(new Date(T0 + TTL * 1000).toISOString());
    const token_ref = credential.payload.token_ref as string;
    expect(tsp.issued.get(token_ref)?.domain).toEqual({
      agent_code: AGENT,
      mandate_id: CART,
      merchant_scope: ["MER-1042"],
      valid_to: "2026-10-21T10:00:00Z",
    });
    const input = { token_ref, order_ref: "ORD-a", merchant_id: "MER-1042", amount_max: 150_000, currency: "RUB", valid_to: credential.payload.valid_to as string };
    expect(tsp.verify(input, credential.payload.cryptogram as string)).toBe(true);
    // В хранилище — хэш, а не значение криптограммы (РП47 п. 3, 10).
    const rec = await store.credentialByOrder(AGENT, CART, "ORD-a");
    expect(rec?.cryptogram_sha256).toBe(sha256Hex(credential.payload.cryptogram as string));
    expect(JSON.stringify(rec)).not.toContain(credential.payload.cryptogram as string);
    expect((await store.tokenByRef(token_ref))?.funding_ref).toMatch(/^fnd_[a-z]{24}$/);
  });

  it("ПС05: повтор того же заказа — тот же реквизит и та же криптограмма, пересчитанная с valid_to записи", async () => {
    const { c, setNow } = setup();
    const a = await c.issue(AGENT, req());
    setNow(T0 + 60_000);
    const b = await c.issue(AGENT, req());
    expect(b).toEqual(a);
  });

  it("один токен на CART: второй заказ — тот же token_ref, другая криптограмма и credential_ref", async () => {
    const { c } = setup();
    const a = await c.issue(AGENT, req());
    const b = await c.issue(AGENT, req({ order_ref: "ORD-b" }));
    if (!a.ok || !b.ok) throw new Error("не выдан");
    expect(b.credential.payload.token_ref).toBe(a.credential.payload.token_ref);
    expect(b.credential.payload.cryptogram).not.toBe(a.credential.payload.cryptogram);
    expect(b.credential.credential_ref).not.toBe(a.credential.credential_ref);
  });

  it("одновременная выдача того же заказа — один реквизит", async () => {
    const { c } = setup();
    const [a, b] = await Promise.all([c.issue(AGENT, req()), c.issue(AGENT, req())]);
    expect(b).toEqual(a);
  });

  it("тот же order_ref с другими значениями в пределах мандата — IDEMPOTENCY_CONFLICT; вне пределов — сначала MANDATE_SCOPE", async () => {
    const { c } = setup({ mandate: cart({ merchant_scope: ["MER-1042", "MER-2"] }) });
    await c.issue(AGENT, req());
    expect(await c.issue(AGENT, req({ currency: "USD" }))).toMatchObject({ ok: false, code: "MANDATE_SCOPE" });
    for (const over of [{ amount_max: 1 }, { merchant_id: "MER-2" }]) {
      expect(await c.issue(AGENT, req(over))).toMatchObject({ ok: false, code: "IDEMPOTENCY_CONFLICT" });
    }
  });

  it("valid_to — не позже срока CART; после него — статус EXPIRED, значение то же", async () => {
    const { c, setNow } = setup({ mandate: cart({ valid_to: "2026-10-20T10:05:00Z" }) });
    const a = await c.issue(AGENT, req());
    if (!a.ok) throw new Error("не выдан");
    expect(a.credential.payload.valid_to).toBe("2026-10-20T10:05:00.000Z");
    setNow(Date.parse("2026-10-20T10:05:00Z"));
    const b = await c.issue(AGENT, req());
    expect(b).toMatchObject({ ok: true, credential: { status: "EXPIRED", payload: a.credential.payload } });
  });

  it("kind SBP — CREDENTIAL_INVALID (СБП — с PS-21), но после мандата и области (РП47 п. 4, ревью КТ1 З3)", async () => {
    const { c } = setup();
    expect(await c.issue(AGENT, req({ kind: "SBP" }))).toMatchObject({ ok: false, code: "CREDENTIAL_INVALID" });
    // Порядок: неизвестный мандат + SBP — MANDATE_NOT_FOUND; не подписан + SBP — по статусу; вне области + SBP — MANDATE_SCOPE.
    expect(await setup({ read: null }).c.issue(AGENT, req({ kind: "SBP" }))).toMatchObject({ ok: false, code: "MANDATE_NOT_FOUND" });
    expect(await setup({ mandate: cart({ status: "PENDING_SIGNATURE" }) }).c.issue(AGENT, req({ kind: "SBP" }))).toMatchObject({
      ok: false,
      code: "PRINCIPAL_SIGNATURE_PENDING",
    });
    expect(await c.issue(AGENT, req({ kind: "SBP", merchant_id: "MER-9" }))).toMatchObject({ ok: false, code: "MANDATE_SCOPE" });
  });

  it("мандат не найден или чужой — MANDATE_NOT_FOUND", async () => {
    expect(await setup({ read: null }).c.issue(AGENT, req())).toMatchObject({ ok: false, code: "MANDATE_NOT_FOUND" });
    expect(await setup().c.issue("nspk:agent:other:v1", req())).toMatchObject({ ok: false, code: "MANDATE_NOT_FOUND" });
  });

  it.each([
    ["PENDING_SIGNATURE", "PRINCIPAL_SIGNATURE_PENDING"],
    ["EXPIRED", "MANDATE_EXPIRED"],
    ["REVOKED", "MANDATE_REVOKED"],
    ["REJECTED", "MANDATE_REVOKED"],
    ["EXHAUSTED", "LIMIT_EXCEEDED"],
    ["UNKNOWN", "STATE_UNAVAILABLE"],
  ])("статус %s — %s", async (status, code) => {
    const { c } = setup({ mandate: cart({ status: status as Mandate["status"] }) });
    expect(await c.issue(AGENT, req())).toMatchObject({ ok: false, code });
  });

  it("INTENT, без согласия на токен, продавец вне области, другая валюта, amount_max выше предела — MANDATE_SCOPE", async () => {
    const cases = [
      setup({ mandate: cart({ type: "INTENT", parent_id: null }) }).c.issue(AGENT, req()),
      setup({ read: { token_consent: false } }).c.issue(AGENT, req()),
      setup({ read: { token_consent: null } }).c.issue(AGENT, req()),
      setup().c.issue(AGENT, req({ merchant_id: "MER-9" })),
      setup().c.issue(AGENT, req({ currency: "USD" })),
      setup().c.issue(AGENT, req({ amount_max: 189_001 })),
    ];
    for (const r of await Promise.all(cases)) expect(r).toMatchObject({ ok: false, code: "MANDATE_SCOPE" });
  });

  it("amount_max ровно на предел CART — выдаётся", async () => {
    expect((await setup().c.issue(AGENT, req({ amount_max: 189_000 }))).ok).toBe(true);
  });

  it("клиент мандата не определён — STATE_UNAVAILABLE", async () => {
    expect(await setup({ read: { client: null } }).c.issue(AGENT, req())).toMatchObject({ ok: false, code: "STATE_UNAVAILABLE" });
  });

  it("повтор: пересчёт криптограммы не совпал с хэшем записи (сменился ключ токен-сервиса) — UPSTREAM_UNAVAILABLE и инцидент, значение не выдаётся", async () => {
    const issuer = createIssuerEmulator();
    const tsp = createTokenServiceEmulator();
    let calls = 0;
    const logs: string[] = [];
    const c = new Credentials({
      mandates: { get: async () => ({ mandate: cart(), client: { participant_code: issuer.participant_code, principal_ref: "pr_alpha" }, token_consent: true }) },
      store: new MemoryCredentialStore(),
      tsp: { issueToken: (i) => tsp.issueToken(i), cryptogram: async (i) => ((await tsp.cryptogram(i)) + (++calls > 1 ? "x" : "")) },
      funding: issuer,
      params: { cryptogram_ttl_sec: TTL },
      now: () => new Date(T0),
      log: (f, m) => logs.push(`${m} ${JSON.stringify(f)}`),
    });
    expect((await c.issue(AGENT, req())).ok).toBe(true);
    expect(await c.issue(AGENT, req())).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
    expect(logs.some((l) => l.startsWith("П5: пересчёт криптограммы не совпал с записью") && l.includes('"incident":true'))).toBe(true);
  });

  it("внешний вызов дольше P5_UPSTREAM_TIMEOUT_MS — UPSTREAM_UNAVAILABLE, реквизит не записан; три вызова — меньше предела обработчика ПАО (РП48 (в))", async () => {
    expect(3 * P5_UPSTREAM_TIMEOUT_MS).toBeLessThan(PAO_HANDLER_BUDGET_MS);
    vi.useFakeTimers();
    try {
      const issuer = createIssuerEmulator();
      const tsp = createTokenServiceEmulator();
      const store = new MemoryCredentialStore();
      const c = new Credentials({
        mandates: { get: async () => ({ mandate: cart(), client: { participant_code: issuer.participant_code, principal_ref: "pr_alpha" }, token_consent: true }) },
        store,
        tsp: { issueToken: (i) => tsp.issueToken(i), cryptogram: () => new Promise<string>(() => {}) },
        funding: issuer,
        params: { cryptogram_ttl_sec: TTL },
        now: () => new Date(T0),
      });
      const p = c.issue(AGENT, req());
      await vi.advanceTimersByTimeAsync(P5_UPSTREAM_TIMEOUT_MS - 1);
      let settled = false;
      void p.then(() => (settled = true));
      await vi.advanceTimersByTimeAsync(0);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(await p).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
      expect(await store.credentialByOrder(AGENT, CART, "ORD-a")).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it("сбой хранилища — STATE_UNAVAILABLE; токен-сервис недоступен — UPSTREAM_UNAVAILABLE", async () => {
    const broken = new MemoryCredentialStore();
    broken.credentialByOrder = () => Promise.reject(new Error("db"));
    expect(await setup({ store: broken }).c.issue(AGENT, req())).toMatchObject({ ok: false, code: "STATE_UNAVAILABLE" });
    expect(await setup({ tspDown: true }).c.issue(AGENT, req())).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
  });

  it("номера карты нет: ссылки — без цифр, в ответе и записях нет серий из 13–19 цифр (инвариант 1)", async () => {
    const { c, store } = setup();
    const r = await c.issue(AGENT, req());
    if (!r.ok) throw new Error("не выдан");
    expect(r.credential.credential_ref).toMatch(/^crd_[a-z]{24}$/);
    expect(r.credential.payload.token_ref).toMatch(/^tok_ag_[a-z]{24}$/);
    // SHA-256 hex — хэш, а не номер: в 64 hex-знаках серия из 13 цифр бывает в ~10 % прогонов; форма — отдельно.
    const { cryptogram_sha256, ...rec } = (await store.credentialByOrder(AGENT, CART, "ORD-a")) ?? {};
    expect(cryptogram_sha256).toMatch(/^[0-9a-f]{64}$/);
    const dump = JSON.stringify([r, rec, await store.tokenByMandate(CART)]);
    expect(dump).not.toMatch(/\d{13,19}/);
  });

  it("погашение — ровно одно из одновременных; повтор — false", async () => {
    const { c, store } = setup();
    const r = await c.issue(AGENT, req());
    if (!r.ok) throw new Error("не выдан");
    const results = await Promise.all([store.consume(r.credential.credential_ref, "op-1"), store.consume(r.credential.credential_ref, "op-2")]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await store.consume(r.credential.credential_ref, "op-3")).toBe(false);
    expect(await c.issue(AGENT, req())).toMatchObject({ ok: true, credential: { status: "USED" } });
  });
});
