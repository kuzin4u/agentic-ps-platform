// П10 Лимиты клиента от банка (PS-20 К1.2, РП45 п. 1, 3): ПИ-8 PUT /participants/v1/principals/{ref}/limits — только
// подписанная банком запись с версией; только вставка, действует наибольшая версия; откат версии — 409; неизвестное поле
// или period — 422; сумма без валюты — 400. Хранилище — в памяти (всегда) и на PostgreSQL (в CI, РП30 п. 7).
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  effectivePeriodLimit,
  MemoryLimitsStore,
  parseLimits,
  periodStart,
  PgLimitsStore,
  type LimitsStore,
  type StoredLimits,
} from "../../src/participants/limits.js";
import { parseParams } from "../../src/shared/config.js";
import { createStand } from "../../src/stand/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

const LIMITS = { per_operation: 100_000, per_period: 300_000, period: "DAY", confirm_above: 150_000, currency: "RUB" } as const;

describe("Limits ПИ-8 по форме (РП45 п. 3)", () => {
  it("принимается запись с суммами и валютой; запись — как прислал банк", () => {
    expect(parseLimits(LIMITS)).toEqual({ ok: true, limits: LIMITS });
    expect(parseLimits({ merchant_categories: ["5411", "5411"] })).toEqual({ ok: true, limits: { merchant_categories: ["5411", "5411"] } });
    expect(parseLimits({})).toEqual({ ok: true, limits: {} });
  });
  it("сумма без валюты, per_period без period и наоборот, не целое ≥ 0 — REQUEST_INVALID (правило совместимости 2)", () => {
    for (const bad of [
      { per_operation: 100 },
      { confirm_above: 100 },
      { per_period: 100, currency: "RUB" },
      { period: "DAY", currency: "RUB" },
      { per_operation: -1, currency: "RUB" },
      { per_operation: 1.5, currency: "RUB" },
      { per_operation: "100", currency: "RUB" },
      { per_operation: 100, currency: "rub" },
      { merchant_categories: ["54111"] },
      { merchant_categories: "5411" },
      null,
      [],
    ]) {
      expect(parseLimits(bad), JSON.stringify(bad)).toEqual({ ok: false, code: "REQUEST_INVALID" });
    }
  });
  it("неизвестное поле или period — LIMITS_UNSUPPORTED: неприменённое ограничение клиента было бы обходом", () => {
    expect(parseLimits({ ...LIMITS, per_week: 1 })).toEqual({ ok: false, code: "LIMITS_UNSUPPORTED" });
    expect(parseLimits({ ...LIMITS, period: "ROLLING_24H" })).toEqual({ ok: false, code: "LIMITS_UNSUPPORTED" });
  });
});

describe("календарный период в часовом поясе (РП45 п. 1)", () => {
  it("граница суток и месяца — в client_limit_period_tz, а не в UTC", () => {
    const t = new Date("2026-10-31T21:30:00Z"); // в Москве уже 1 ноября 00:30
    expect(periodStart("DAY", "Europe/Moscow", t)).toBe("2026-11-01");
    expect(periodStart("MONTH", "Europe/Moscow", t)).toBe("2026-11");
    expect(periodStart("DAY", "UTC", t)).toBe("2026-10-31");
    expect(periodStart("MONTH", "UTC", t)).toBe("2026-10");
  });
  it("параметр — имя пояса IANA; неизвестное — отказ запуска, не UTC по умолчанию", () => {
    const base = JSON.parse(readFileSync("config/params.stand.json", "utf8")) as Record<string, unknown>;
    expect(parseParams(base).client_limit_period_tz).toBe("Europe/Moscow");
    expect(() => parseParams({ ...base, client_limit_period_tz: "Mars/Olympus" })).toThrow(/client_limit_period_tz/);
    expect(() => parseParams({ ...base, client_limit_period_tz: "" })).toThrow(/client_limit_period_tz/);
  });
});

const rec = (version: number, over: Partial<StoredLimits> = {}): StoredLimits => ({
  participant_code: "bank:a",
  kid: "kid-1",
  principal_ref: "prn_7f3c9a",
  version,
  limits: LIMITS,
  issued_at: "2026-10-19T10:00:00.000Z",
  signature: `sig-${version}`,
  received_at: "2026-10-19T10:00:01.000Z",
  ...over,
});

function storeContract(name: string, make: () => Promise<LimitsStore>) {
  describe(`хранилище лимитов: ${name}`, () => {
    it("только вставка с версией: выше — inserted, та же запись — replayed, откат и другая запись той же версии — conflict", async () => {
      const s = await make();
      const c = { participant_code: "bank:a", principal_ref: "prn_7f3c9a" };
      expect(await s.current(c)).toBeUndefined();
      expect(await s.put(rec(2))).toBe("inserted");
      expect(await s.put(rec(2, { received_at: "2026-10-19T11:00:00.000Z" }))).toBe("replayed");
      expect(await s.put(rec(2, { signature: "sig-other" }))).toBe("conflict");
      expect(await s.put(rec(2, { limits: { ...LIMITS, per_operation: 1 } }))).toBe("conflict");
      // Подстановка старой, более мягкой подписанной записи (РП45 п. 1).
      expect(await s.put(rec(1, { limits: { ...LIMITS, per_period: 10_000_000 } }))).toBe("conflict");
      expect(await s.put(rec(3, { limits: { per_operation: 5_000, currency: "RUB" } }))).toBe("inserted");
      expect((await s.current(c))?.version).toBe(3);
      expect((await s.current(c))?.limits).toEqual({ per_operation: 5_000, currency: "RUB" });
      // История — все версии по возрастанию: правило «расширение со следующего периода» (РП45 п. 1).
      expect((await s.history(c)).map((r) => r.version)).toEqual([2, 3]);
      expect(await s.history({ participant_code: "bank:x", principal_ref: "prn_none" })).toEqual([]);
    });
    it("пара «банк + клиент»: записи другого банка для того же principal_ref — отдельные", async () => {
      const s = await make();
      expect(await s.put(rec(5, { principal_ref: "prn_pair", participant_code: "bank:a" }))).toBe("inserted");
      expect(await s.put(rec(1, { principal_ref: "prn_pair", participant_code: "bank:b" }))).toBe("inserted");
      expect((await s.current({ participant_code: "bank:b", principal_ref: "prn_pair" }))?.version).toBe(1);
      expect(await s.current({ participant_code: "bank:c", principal_ref: "prn_pair" })).toBeUndefined();
    });
  });
}

storeContract("память", async () => new MemoryLimitsStore());

describe.skipIf(!DATABASE_URL)("лимиты на PostgreSQL (sql/105)", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await openTestDb("limits");
  });
  afterAll(async () => {
    await db?.close();
  });
  storeContract("PostgreSQL", async () => new PgLimitsStore(db.pool));
  it("записи не меняются и не удаляются (только вставка, триггер)", async () => {
    const s = new PgLimitsStore(db.pool);
    await s.put(rec(1, { principal_ref: "prn_guard" }));
    await expect(db.pool.query("UPDATE participant_limits SET version = 9 WHERE principal_ref = 'prn_guard'")).rejects.toThrow(/только вставка/);
    await expect(db.pool.query("DELETE FROM participant_limits WHERE principal_ref = 'prn_guard'")).rejects.toThrow(/только вставка/);
    await expect(db.pool.query("TRUNCATE participant_limits")).rejects.toThrow(/только вставка/);
  });
});

describe("ПИ-8 PUT /participants/v1/principals/{ref}/limits (стенд, эмулятор эмитента)", () => {
  it("подписанная запись — 200 {principal_ref, version}; повтор — 200; откат версии — 409; поле не того вида — 422 / 400", async () => {
    const stand = createStand();
    // Часы стенда стоят: повтор банка — та же запись с тем же issued_at.
    stand.setClock(new Date("2026-10-19T10:00:00Z"));
    try {
      expect(await stand.issuer.setLimits("prn_7f3c9a", LIMITS, 2)).toEqual({ statusCode: 200, body: { principal_ref: "prn_7f3c9a", version: 2 } });
      expect(await stand.issuer.setLimits("prn_7f3c9a", LIMITS, 2)).toMatchObject({ statusCode: 200 });
      expect(await stand.issuer.setLimits("prn_7f3c9a", { ...LIMITS, per_period: 10_000_000 }, 1)).toEqual({
        statusCode: 409,
        body: { code: "LIMITS_VERSION_CONFLICT" },
      });
      expect(await stand.issuer.setLimits("prn_7f3c9a", { ...LIMITS, period: "WEEK" }, 3)).toEqual({ statusCode: 422, body: { code: "LIMITS_UNSUPPORTED" } });
      expect(await stand.issuer.setLimits("prn_7f3c9a", { per_operation: 1 }, 3)).toEqual({ statusCode: 400, body: { code: "REQUEST_INVALID" } });
      expect(await stand.issuer.setLimits("not a ref", LIMITS, 3)).toEqual({ statusCode: 400, body: { code: "REQUEST_INVALID" } });
    } finally {
      await stand.close();
    }
  });
  it("без подписи банка или с чужой записью — 401 SIGNATURE_INVALID: неаутентифицированной точки нет", async () => {
    const stand = createStand();
    try {
      const body = {
        participant_code: stand.issuer.participant_code,
        kid: stand.issuer.trustedKey.kid,
        version: 1,
        limits: LIMITS,
        issued_at: "2026-10-19T10:00:00.000Z",
        signature: "A".repeat(86),
      };
      const res = await stand.app.inject({ method: "PUT", url: "/participants/v1/principals/prn_7f3c9a/limits", payload: body });
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual({ code: "SIGNATURE_INVALID" });
      // Лишнее поле не подписано — отказ, а не пропуск.
      const extra = await stand.app.inject({ method: "PUT", url: "/participants/v1/principals/prn_7f3c9a/limits", payload: { ...body, note: "x" } });
      expect(extra.statusCode).toBe(400);
      // GET — с подписью запроса участника (часть 2): без неё лимиты клиента не отдаются.
      expect((await stand.app.inject({ method: "GET", url: "/participants/v1/principals/prn_7f3c9a/limits" })).statusCode).toBe(404);
    } finally {
      await stand.close();
    }
  });
});

describe("лимит за период по истории версий: расширение — со следующего периода (РП45 п. 1, /audit № 1)", () => {
  const TZ = "Europe/Moscow";
  const v = (limits: Record<string, unknown>, received_at: string) => ({ limits: limits as never, received_at });
  const DAY3 = { per_period: 300_000, period: "DAY", currency: "RUB" };
  const MONTH3 = { per_period: 300_000, period: "MONTH", currency: "RUB" };
  const at = (iso: string) => new Date(iso);

  it("снятие per_period — прежний лимит до конца текущего периода, со следующего — снят", () => {
    const h = [v(DAY3, "2026-10-01T09:00:00Z"), v({ per_operation: 1_000, currency: "RUB" }, "2026-10-19T09:00:00Z")];
    expect(effectivePeriodLimit(h, TZ, at("2026-10-19T20:59:00Z"))).toEqual(DAY3); // 23:59 МСК — тот же день
    expect(effectivePeriodLimit(h, TZ, at("2026-10-19T21:00:00Z"))).toBeUndefined(); // 00:00 МСК — следующий
  });
  it("смена MONTH → DAY — месячный до конца месяца, дневной — с 1-го числа (расход за месяц учтён)", () => {
    const h = [v(MONTH3, "2026-09-01T09:00:00Z"), v(DAY3, "2026-10-19T09:00:00Z")];
    expect(effectivePeriodLimit(h, TZ, at("2026-10-31T20:59:00Z"))).toEqual(MONTH3);
    expect(effectivePeriodLimit(h, TZ, at("2026-10-31T21:00:00Z"))).toEqual(DAY3);
  });
  it("смена валюты — как смена вида; новый per_period там, где не было, и смена суммы при том же виде — сразу", () => {
    expect(effectivePeriodLimit([v(DAY3, "2026-10-01T00:00:00Z"), v({ ...DAY3, currency: "USD" }, "2026-10-19T09:00:00Z")], TZ, at("2026-10-19T10:00:00Z"))).toEqual(DAY3);
    expect(effectivePeriodLimit([v({}, "2026-10-01T00:00:00Z"), v(DAY3, "2026-10-19T09:00:00Z")], TZ, at("2026-10-19T10:00:00Z"))).toEqual(DAY3);
    const more = { ...DAY3, per_period: 900_000 };
    // Сумма — сразу в записи; расширение суммы в периоде держит счёт периода (StateService.reserveClient).
    expect(effectivePeriodLimit([v(DAY3, "2026-10-01T00:00:00Z"), v(more, "2026-10-19T09:00:00Z")], TZ, at("2026-10-19T10:00:00Z"))).toEqual(more);
    expect(effectivePeriodLimit([], TZ, at("2026-10-19T10:00:00Z"))).toBeUndefined();
  });
  it("несколько версий в одном периоде: снятие, затем возврат того же вида — действует последний того же вида", () => {
    const h = [v(DAY3, "2026-10-01T00:00:00Z"), v({}, "2026-10-19T08:00:00Z"), v({ ...DAY3, per_period: 100_000 }, "2026-10-19T09:00:00Z")];
    expect(effectivePeriodLimit(h, TZ, at("2026-10-19T10:00:00Z"))).toEqual({ ...DAY3, per_period: 100_000 });
  });
});
