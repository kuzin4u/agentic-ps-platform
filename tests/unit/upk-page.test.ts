// Страница УПК стенда (PS-19 ч. 3 К2.1; РП51 п. 15–16, «Дополнения» п. 8; инварианты 1, 7; правило совместимости 3):
// итог из записи П6, выбор инструмента (СБП — только при upk_sbp_enabled), одноразовый код от эмитента, решение —
// подпись UPK и ПИ-8 с instrument_chosen. Без кода, с неверным, сгоревшим, чужим или истёкшим кодом — отказ без ПИ-8.
import { afterEach, describe, expect, it } from "vitest";
import { MemoryConfirmationStore, newConfirmationId, totalsHash, type ConfirmationRecord } from "../../src/confirm/index.js";
import { UPK_CODE_MAX_ATTEMPTS, UpkCodes } from "../../src/env/upk/codes.js";
import { createUpkEmulator } from "../../src/env/upk/index.js";
import { createUpkPage, type UpkPageSettings } from "../../src/env/upk/page.js";
import { TrustedParticipants } from "../../src/participants/trusted.js";

const T0 = Date.parse("2026-10-22T10:00:00.000Z");
const HOLD_MS = 900_000;
const upk = createUpkEmulator();
const trusted = new TrustedParticipants([upk.trustedKey], { stand: true });

function setup(opts: { sbp?: boolean; settings?: UpkPageSettings; failGet?: boolean } = {}) {
  let t = T0;
  const store = new MemoryConfirmationStore();
  const codes = new UpkCodes();
  const sent: { id: string; body: Record<string, unknown> }[] = [];
  const app = createUpkPage({
    upk,
    confirmations: {
      get: async (id) => {
        if (opts.failGet) throw new Error("П6 недоступен");
        return store.get(id);
      },
    },
    codes,
    async submit(id, body) {
      sent.push({ id, body });
      return { statusCode: 200, body: { confirmation_id: id, status: body.decision === "APPROVE" ? "APPROVED" : "REJECTED" } };
    },
    sbpEnabled: opts.sbp ?? false,
    now: () => new Date(t),
    ...(opts.settings ? { settings: opts.settings } : {}),
  });
  const request = (over: Partial<ConfirmationRecord> = {}) =>
    store.create({
      confirmation_id: newConfirmationId(),
      agent_code: "nspk:agent:buyref-01:v3",
      mandate_id: "mnd_00000000-0000-4000-8000-000000000001",
      merchant_id: "MER-1042",
      amount: 340_000,
      currency: "RUB",
      order_ref: "ORD-77a1",
      split_detected: false,
      status: "PENDING",
      created_at: new Date(T0).toISOString(),
      expires_at: new Date(T0 + HOLD_MS).toISOString(),
      confirmation_ref: null,
      decision: null,
      op_ref: null,
      ...over,
    });
  const get = (id: string, query = "") => app.inject({ method: "GET", url: `/c/${id}${query}` });
  const post = (id: string, form: Record<string, string>) =>
    app.inject({
      method: "POST",
      url: `/c/${id}`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams(form).toString(),
    });
  return { app, store, codes, sent, request, get, post, setNow: (ms: number) => (t = ms) };
}

let ctx: ReturnType<typeof setup> | undefined;
afterEach(async () => {
  await ctx?.app.close();
  ctx = undefined;
});

describe("страница УПК: итог, язык и бренд (РП51 п. 15, правило совместимости 3)", () => {
  it("GET — итог из записи П6 (продавец, сумма с валютой, заказ, срок), форма с кодом; номера карты нет", async () => {
    ctx = setup();
    const r = await ctx.request();
    const res = await ctx.get(r.confirmation_id);
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^text\/html/);
    expect(res.headers["cache-control"]).toBe("no-store");
    const html = res.body;
    expect(html).toContain('<html lang="ru">');
    expect(html).toContain("Подтверждение покупки");
    expect(html).toMatch(/data-merchant>MER-1042</);
    expect(html).toMatch(/data-amount>3\s?400,00\s?₽</);
    expect(html).toMatch(/data-order>ORD-77a1</);
    expect(html).toContain(`data-expires>${r.expires_at}<`);
    expect(html).toContain('name="code"');
    expect(html, "номера карты нет (инвариант 1)").not.toMatch(/\d{13,19}/);
    expect(html, "ни ссылки, ни агента на странице").not.toMatch(/cr_|nspk:agent/);
  });

  it("?lang=en — английский; переключатель языка; бренд — название, цвет, логотип; разметка экранируется", async () => {
    ctx = setup({ settings: { lang: "ru", brand: { name: "Bank <b>&", color: "#AA3300", logo_url: "https://cdn.example/logo.svg" } } });
    const r = await ctx.request();
    const en = (await ctx.get(r.confirmation_id, "?lang=en")).body;
    expect(en).toContain('<html lang="en">');
    expect(en).toContain("Purchase confirmation");
    expect(en).toMatch(/data-amount>RUB\s?3,400\.00</);
    expect(en).toContain('href="?lang=ru"');
    expect(en).toContain("data-brand>Bank &lt;b&gt;&amp;<");
    expect(en).toContain("background:#AA3300");
    expect(en).toContain('<img src="https://cdn.example/logo.svg"');
    const ru = (await ctx.get(r.confirmation_id)).body;
    expect(ru).toContain('href="?lang=en"');
    expect((await ctx.get(r.confirmation_id, "?lang=de")).body, "неизвестный язык — по настройке").toContain('<html lang="ru">');
  });

  it("неверная настройка бренда или языка — отказ запуска эмулятора", () => {
    const bad: UpkPageSettings[] = [
      { lang: "de" as never, brand: { name: "x", color: "#000000" } },
      { lang: "ru", brand: { name: "", color: "#000000" } },
      { lang: "ru", brand: { name: "x", color: "red;}body{x" } },
      { lang: "ru", brand: { name: "x", color: "#000000", logo_url: "http://cdn/logo" } },
    ];
    for (const settings of bad) expect(() => setup({ settings })).toThrow(/страница УПК/);
  });

  it("СБП — только при upk_sbp_enabled (РП51 п. 16): false — только карта; true — карта и СБП", async () => {
    ctx = setup();
    const r = await ctx.request();
    const off = (await ctx.get(r.confirmation_id)).body;
    expect(off).toContain('value="CARD"');
    expect(off).not.toContain('value="SBP"');
    await ctx.app.close();
    ctx = setup({ sbp: true });
    const r2 = await ctx.request();
    expect((await ctx.get(r2.confirmation_id)).body).toContain('value="SBP"');
  });

  it("неизвестный и не по форме — 404; не в ожидании или после срока — 409 без формы; сбой П6 — 503", async () => {
    ctx = setup();
    expect((await ctx.get(newConfirmationId())).statusCode).toBe(404);
    expect((await ctx.get("../../participants")).statusCode).toBe(404);
    const r = await ctx.request();
    ctx.setNow(T0 + HOLD_MS);
    const late = await ctx.get(r.confirmation_id);
    expect(late.statusCode).toBe(409);
    expect(late.body).not.toContain("<form");
    await ctx.app.close();
    ctx = setup({ failGet: true });
    expect((await ctx.get(newConfirmationId())).statusCode).toBe(503);
  });
});

describe("страница УПК: решение человека (РП51 п. 12–16; инвариант 7)", () => {
  it("верный код — подпись UPK и ПИ-8 с instrument_chosen над итогом записи; ответ — подтверждено", async () => {
    ctx = setup();
    const r = await ctx.request();
    const code = ctx.codes.issue(r.confirmation_id, r.expires_at);
    const res = await ctx.post(r.confirmation_id, { code, instrument: "CARD", decision: "APPROVE" });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("data-status>APPROVED<");
    expect(ctx.sent).toHaveLength(1);
    const { id, body } = ctx.sent[0]!;
    expect(id).toBe(r.confirmation_id);
    expect(body).toMatchObject({
      participant_code: "stand:upk-emulator",
      kid: upk.trustedKey.kid,
      decision: "APPROVE",
      totals_hash: totalsHash(r),
      decided_at: new Date(T0).toISOString(),
      instrument_chosen: "CARD",
    });
    const { signature, ...record } = body as Record<string, string>;
    const signed = { ...record, confirmation_id: r.confirmation_id } as unknown as Parameters<typeof trusted.verifyConfirmation>[0];
    expect(trusted.verifyConfirmation(signed, signature!)).toBe(true);
  });

  it("отказ человека — REJECT с выбранным инструментом", async () => {
    ctx = setup();
    const r = await ctx.request();
    const code = ctx.codes.issue(r.confirmation_id, r.expires_at);
    const res = await ctx.post(r.confirmation_id, { code, instrument: "CARD", decision: "REJECT", lang: "en" });
    expect(res.body).toContain("Purchase declined.");
    expect(ctx.sent[0]!.body).toMatchObject({ decision: "REJECT", instrument_chosen: "CARD" });
  });

  it("без кода и с неверным кодом — отказ страницы без ПИ-8; ответ на неверный и сгоревший — одинаковый", async () => {
    ctx = setup();
    const r = await ctx.request();
    const code = ctx.codes.issue(r.confirmation_id, r.expires_at);
    const wrong = code === "000000" ? "111111" : "000000";
    const noCode = await ctx.post(r.confirmation_id, { instrument: "CARD", decision: "APPROVE" });
    expect(noCode.statusCode).toBe(400);
    const first = await ctx.post(r.confirmation_id, { code: wrong, instrument: "CARD", decision: "APPROVE" });
    expect(first.statusCode).toBe(403);
    for (let i = 1; i < UPK_CODE_MAX_ATTEMPTS; i++) await ctx.post(r.confirmation_id, { code: wrong, instrument: "CARD", decision: "APPROVE" });
    const burned = await ctx.post(r.confirmation_id, { code, instrument: "CARD", decision: "APPROVE" });
    expect([burned.statusCode, burned.body], "сгоревший — тот же ответ, что неверный").toEqual([first.statusCode, first.body]);
    expect(ctx.sent, "ПИ-8 не вызывался").toEqual([]);
  });

  it("SBP при upk_sbp_enabled: false — отказ страницы без ПИ-8, код не сгорает; при true — SBP уходит в ПИ-8", async () => {
    ctx = setup();
    const r = await ctx.request();
    const code = ctx.codes.issue(r.confirmation_id, r.expires_at);
    expect((await ctx.post(r.confirmation_id, { code, instrument: "SBP", decision: "APPROVE" })).statusCode).toBe(400);
    expect((await ctx.post(r.confirmation_id, { code, instrument: "PAN", decision: "APPROVE" })).statusCode).toBe(400);
    expect(ctx.sent).toEqual([]);
    expect((await ctx.post(r.confirmation_id, { code, instrument: "CARD", decision: "APPROVE" })).statusCode, "код цел").toBe(200);
    await ctx.app.close();
    ctx = setup({ sbp: true });
    const r2 = await ctx.request();
    const code2 = ctx.codes.issue(r2.confirmation_id, r2.expires_at);
    expect((await ctx.post(r2.confirmation_id, { code: code2, instrument: "SBP", decision: "APPROVE" })).statusCode).toBe(200);
    expect(ctx.sent[0]!.body.instrument_chosen).toBe("SBP");
  });

  it("код одноразовый: после верного ввода повтор тем же кодом не принимается", async () => {
    ctx = setup();
    const r = await ctx.request();
    const code = ctx.codes.issue(r.confirmation_id, r.expires_at);
    expect((await ctx.post(r.confirmation_id, { code, instrument: "CARD", decision: "APPROVE" })).statusCode).toBe(200);
    expect(ctx.codes.redeem(r.confirmation_id, code, new Date(T0).toISOString())).toBe(false);
  });

  it("запрос не в ожидании или после срока — 409 до кода, без ПИ-8", async () => {
    ctx = setup();
    const r = await ctx.request();
    const code = ctx.codes.issue(r.confirmation_id, r.expires_at);
    ctx.setNow(T0 + HOLD_MS);
    expect((await ctx.post(r.confirmation_id, { code, instrument: "CARD", decision: "APPROVE" })).statusCode).toBe(409);
    expect(ctx.sent).toEqual([]);
  });
});

describe("одноразовый код (РП51 «Дополнения» п. 8, решение владельца 22.10)", () => {
  const ID = newConfirmationId();
  const EXP = new Date(T0 + HOLD_MS).toISOString();
  const AT = new Date(T0).toISOString();

  it("3 неверных — код сгорел, верный уже не принимается; новый код — только новой выдачей", () => {
    const codes = new UpkCodes();
    const code = codes.issue(ID, EXP);
    const wrong = code === "000000" ? "111111" : "000000";
    for (let i = 0; i < UPK_CODE_MAX_ATTEMPTS; i++) expect(codes.redeem(ID, wrong, AT)).toBe(false);
    expect(codes.redeem(ID, code, AT)).toBe(false);
    const fresh = codes.issue(ID, EXP);
    expect(codes.redeem(ID, fresh, AT)).toBe(true);
  });

  it("два неверных, затем верный — принят (сгорает на третьем неверном)", () => {
    const codes = new UpkCodes();
    const code = codes.issue(ID, EXP);
    const wrong = code === "000000" ? "111111" : "000000";
    codes.redeem(ID, wrong, AT);
    codes.redeem(ID, wrong, AT);
    expect(codes.redeem(ID, code, AT)).toBe(true);
  });

  it("код чужого запроса не принимается и не расходует его код", () => {
    const codes = new UpkCodes();
    const other = newConfirmationId();
    const mine = codes.issue(ID, EXP);
    const theirs = codes.issue(other, EXP);
    if (theirs !== mine) expect(codes.redeem(ID, theirs, AT)).toBe(false);
    expect(codes.redeem(other, theirs, AT)).toBe(true);
    expect(codes.redeem(ID, mine, AT)).toBe(true);
  });

  it("после expires_at не принимается; без выдачи — не принимается", () => {
    const codes = new UpkCodes();
    const code = codes.issue(ID, EXP);
    expect(codes.redeem(ID, code, EXP)).toBe(false);
    expect(codes.redeem(newConfirmationId(), code, AT)).toBe(false);
  });

  it("новая выдача заменяет прежний код", () => {
    const codes = new UpkCodes();
    const old = codes.issue(ID, EXP);
    const fresh = codes.issue(ID, EXP);
    if (old !== fresh) expect(codes.redeem(ID, old, AT)).toBe(false);
    expect(codes.redeem(ID, fresh, AT)).toBe(true);
  });
});
