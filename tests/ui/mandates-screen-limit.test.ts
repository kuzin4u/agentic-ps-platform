// Экран мандатов: находки CodeQL PR #95 (К1.4). № 88 — грубый лимит частоты по адресу на всё приложение экрана
// (как РП73: @fastify/rate-limit, окно 30 с, IPv6 — /64), 429 — страница для человека с Retry-After ≤ 30 и no-store, до
// сессии и порта; величина — параметр модуля (стенд — 600, банк задаёт свою). № 89 — revocation_ref из равномерно выбранных
// букв (randomInt), без смещения остатка от деления.
import { describe, expect, it } from "vitest";
import { STAND_SCREEN_RATE_LIMIT_PER_30S } from "../../src/env/issuer/screen.js";
import { createMandatesScreen, newRevocationRef } from "../../src/ui/mandates/index.js";
import type { MandatesScreenPort } from "../../src/ui/mandates/port.js";
import { UI_CSP } from "../../src/ui/shared/index.js";

const T0 = Date.parse("2026-11-02T10:00:00.000Z");
const TTL = { login_ttl_sec: 120, session_ttl_sec: 900 };

function setup(limit: number) {
  const calls: string[] = [];
  const port: MandatesScreenPort = {
    mandates: async () => (calls.push("mandates"), []),
    mandate: async () => (calls.push("mandate"), undefined),
    decide: async () => (calls.push("decide"), { kind: "NOT_FOUND" }),
    revoke: async () => (calls.push("revoke"), { kind: "NOT_FOUND" }),
    revokeAll: async () => (calls.push("revokeAll"), { revoked: 0 }),
  };
  const screen = createMandatesScreen({ port, ttl: TTL, rate_limit_per_30s: limit, now: () => new Date(T0) });
  const from = (ip: string, url: string) => screen.app.inject({ method: "GET", url, remoteAddress: ip });
  return { screen, calls, from };
}

describe("экран мандатов: лимит частоты по адресу (CodeQL #88)", () => {
  it("вход по ссылке: сверх предела — 429-страница с Retry-After ≤ 30, no-store, CSP; токен не погашается", async () => {
    const { screen, from } = setup(3);
    for (let i = 0; i < 3; i++) expect((await from("198.51.100.7", `/login/${"A".repeat(43)}`)).statusCode).toBe(401);
    const path = screen.loginPath("cl_limit_owner");
    const limited = await from("198.51.100.7", path);
    expect(limited.statusCode).toBe(429);
    const ra = Number(limited.headers["retry-after"]);
    expect(ra).toBeGreaterThan(0);
    expect(ra).toBeLessThanOrEqual(30);
    expect(limited.headers["cache-control"]).toBe("no-store");
    expect(limited.headers["content-security-policy"]).toBe(UI_CSP);
    expect(limited.headers["content-type"]).toContain("text/html");
    expect(limited.body).toContain("Слишком много обращений");
    expect(limited.headers["set-cookie"]).toBeUndefined();
    // Другой адрес — свой счётчик: ссылка не погашена лимитом и открывает сессию.
    expect((await from("198.51.100.8", path)).statusCode).toBe(303);
  });

  it("лимит — на всё приложение и до порта: исчерпан на одном маршруте — 429 на другом, порт не вызывается", async () => {
    const { calls, from } = setup(2);
    await from("203.0.113.5", "/");
    await from("203.0.113.5", `/m/mnd_00000001-0000-4000-8000-000000000000`);
    const r = await from("203.0.113.5", "/revoke-all?lang=en");
    expect(r.statusCode).toBe(429);
    expect(r.body).toContain("Too many requests");
    expect(calls).toEqual([]);
  });

  it("IPv6 — по /64: адреса одной /64 делят счётчик, другой /64 — свой", async () => {
    const { from } = setup(1);
    expect((await from("2001:db8:1:1::1", "/")).statusCode).toBe(401);
    expect((await from("2001:db8:1:1::2", "/")).statusCode).toBe(429);
    expect((await from("2001:db8:1:2::1", "/")).statusCode).toBe(401);
  });

  it("предел — целое ≥ 1, иначе отказ запуска; стенд — 600", () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) expect(() => setup(bad)).toThrow(/rate_limit_per_30s/);
    expect(STAND_SCREEN_RATE_LIMIT_PER_30S).toBe(600);
  });
});

describe("revocation_ref — равномерные буквы (CodeQL #89)", () => {
  it("rva_ + 24 буквы a–z; доля w–z — 4/26 в пределах 5 σ (остаток от деления байта дал бы 36/256 — ≈ 11 σ)", () => {
    const N = 4000;
    let wz = 0;
    let total = 0;
    for (let i = 0; i < N; i++) {
      const ref = newRevocationRef();
      expect(ref).toMatch(/^rva_[a-z]{24}$/);
      for (const ch of ref.slice(4)) {
        total++;
        if (ch >= "w") wz++;
      }
    }
    const p = 4 / 26;
    const sigma = Math.sqrt(total * p * (1 - p));
    expect(Math.abs(wz - total * p)).toBeLessThan(5 * sigma);
  });
});
