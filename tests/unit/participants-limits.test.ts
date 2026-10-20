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
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { TrustedParticipants } from "../../src/participants/trusted.js";
import { ParticipantRequestVerifier } from "../../src/participants/verify.js";
import { buildServer } from "../../src/server.js";
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
  it("гонка версий на двух экземплярах (РП45 доп. п. 10): PUT v2 ‖ v3 — действует v3; v3 всегда записан, v2 — записан или 409", async () => {
    const s1 = new PgLimitsStore(db.pool);
    const s2 = new PgLimitsStore(db.reopen());
    for (let i = 0; i < 10; i++) {
      const principal_ref = `prn_race_${i}`;
      const [r2, r3] = await Promise.all([s1.put(rec(2, { principal_ref })), s2.put(rec(3, { principal_ref }))]);
      expect(r3, "старшая версия не записана").toBe("inserted");
      expect(["inserted", "conflict"]).toContain(r2);
      expect((await s1.current({ participant_code: "bank:a", principal_ref }))?.version, "действует не старшая версия").toBe(3);
    }
  });
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
      // GET — с подписью запроса участника (РП46 (в)): без неё лимиты клиента не отдаются.
      const get = await stand.app.inject({ method: "GET", url: "/participants/v1/principals/prn_7f3c9a/limits" });
      expect(get.statusCode).toBe(401);
      expect(get.json()).toEqual({ code: "SIGNATURE_INVALID" });
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

describe("ПИ-8 GET /participants/v1/principals/{ref}/limits с подписью запроса участника (RFC 9421, РП46 (в))", () => {
  const PATH = "/participants/v1/principals/prn_7f3c9a/limits";
  const T = new Date("2026-10-19T10:00:00Z");

  it("подписанный запрос — 200 и действующая запись (наибольшая версия) с подписью банка; записи нет — 404 LIMITS_NOT_FOUND", async () => {
    const stand = createStand();
    stand.setClock(T);
    try {
      expect(await stand.issuer.getLimits("prn_7f3c9a")).toEqual({ statusCode: 404, body: { code: "LIMITS_NOT_FOUND" } });
      await stand.issuer.setLimits("prn_7f3c9a", LIMITS, 1);
      await stand.issuer.setLimits("prn_7f3c9a", { ...LIMITS, per_period: 200_000 }, 2);
      const r = await stand.issuer.getLimits("prn_7f3c9a");
      expect(r.statusCode).toBe(200);
      expect(r.body).toMatchObject({
        participant_code: stand.issuer.participant_code,
        principal_ref: "prn_7f3c9a",
        version: 2,
        limits: { ...LIMITS, per_period: 200_000 },
      });
      expect((r.body as { signature: string }).signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
    } finally {
      await stand.close();
    }
  });

  it("повтор nonce, метка вне окна, чужой путь в подписи, заголовок не из состава — 401 одним кодом", async () => {
    const stand = createStand();
    stand.setClock(T);
    try {
      await stand.issuer.setLimits("prn_7f3c9a", LIMITS, 1);
      const sign = (at = T, path = PATH) => stand.issuer.signRequest("GET", path, "", at);
      const get = (headers: Record<string, string>) => stand.app.inject({ method: "GET", url: PATH, headers });
      const h = sign();
      expect((await get(h)).statusCode).toBe(200);
      expect((await get(h)).statusCode, "повтор nonce принят").toBe(401);
      const late = new Date(T.getTime() - (stand.params.signature_skew_sec + 1) * 1000);
      expect((await get(sign(late))).statusCode, "метка вне окна принята").toBe(401);
      expect((await get(sign(T, "/participants/v1/principals/prn_other1/limits"))).statusCode, "подпись чужого пути принята").toBe(401);
      const swapped = sign();
      swapped["signature-input"] = swapped["signature-input"]!.replace('"x-participant-code"', '"x-agent-code"');
      expect((await get({ ...swapped, "x-agent-code": stand.issuer.participant_code })).statusCode, "состав подписи не по профилю принят").toBe(401);
      expect((await get({ ...sign(), "x-participant-code": "bank:other" })).statusCode, "подмена участника принята").toBe(401);
    } finally {
      await stand.close();
    }
  });

  it("пара другого банка — 404, как нет записи: участник — из проверенной подписи, не из пути", async () => {
    const emu = createIssuerEmulator();
    const trusted = new TrustedParticipants([emu.trustedKey], { stand: true });
    const store = new MemoryLimitsStore();
    await store.put(rec(5, { participant_code: "bank:other" }));
    const app = buildServer({
      env: "dev",
      participants: {
        trusted,
        consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
        params: { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 },
        limits: store,
        requests: new ParticipantRequestVerifier(trusted, { skewSec: 300, now: () => T }),
      },
    });
    try {
      const res = await app.inject({ method: "GET", url: PATH, headers: emu.signRequest("GET", PATH, "", T) });
      expect(res.statusCode, "банк прочитал запись клиента другого банка").toBe(404);
      expect(res.json()).toEqual({ code: "LIMITS_NOT_FOUND" });
    } finally {
      await app.close();
    }
  });
});

