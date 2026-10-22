// Страница УПК стенда (РП51 п. 15–16, ПИ-6): человек видит итог из записи П6, выбирает инструмент и подтверждает
// одноразовым кодом от эмитента. Решение эмулятор подписывает ключом stand:upk-emulator и шлёт по ПИ-8 с
// instrument_chosen. Язык (ru / en) и бренд — настройка эмулятора (правило совместимости 3); в ADP, ПАО и П6 текстов и
// бренда нет. Номера карты и счёта на странице нет (инвариант 1); сумма — из записи (минимальные единицы и валюта).
import Fastify, { type FastifyInstance, type FastifyReply } from "fastify";
import { CONFIRMATION_ID, totalsHash, type ConfirmationInstrument, type ConfirmationRecord } from "../../confirm/model.js";
import type { UpkCodes } from "./codes.js";
import type { UpkEmulator } from "./index.js";

export type UpkLang = "ru" | "en";

/** Бренд оператора УПК: название, цвет (#rrggbb), логотип по ссылке https://. */
export interface UpkBrand {
  readonly name: string;
  readonly color: string;
  readonly logo_url?: string;
}

export interface UpkPageSettings {
  /** Язык по умолчанию; переключение — `?lang=` или поле формы `lang`. */
  readonly lang: UpkLang;
  readonly brand: UpkBrand;
}

export const UPK_DEFAULT_SETTINGS: UpkPageSettings = { lang: "ru", brand: { name: "УПК стенда", color: "#1a5fb4" } };

export interface UpkPageDeps {
  readonly upk: UpkEmulator;
  /** Записи П6 только для чтения: итог — из записи, а не со слов агента (инвариант 5). */
  readonly confirmations: { get(id: string): Promise<ConfirmationRecord | undefined> };
  readonly codes: UpkCodes;
  /** ПИ-8 POST /participants/v1/confirmations/{id} Платформы (на стенде — inject в сервер). */
  submit(confirmation_id: string, body: Record<string, unknown>): Promise<{ statusCode: number; body: unknown }>;
  /** upk_sbp_enabled (РП51 п. 16): при false — только карта. */
  readonly sbpEnabled: boolean;
  readonly now: () => Date;
  readonly settings?: UpkPageSettings;
}

const TEXT = {
  ru: {
    title: "Подтверждение покупки",
    merchant: "Продавец",
    amount: "Сумма",
    order: "Заказ",
    until: "Действует до",
    instrument: "Способ оплаты",
    CARD: "Карта",
    SBP: "СБП",
    code: "Код из банка",
    approve: "Подтвердить",
    reject: "Отклонить",
    approved: "Покупка подтверждена. Агент продолжит оплату у продавца.",
    rejected: "Покупка отклонена.",
    notPending: "Запрос уже обработан или истёк",
    notFound: "Запрос не найден",
    codeRejected: "Код не принят. Получите новый код в банке.",
    badForm: "Выберите способ оплаты и решение",
    unavailable: "Сервис временно недоступен, попробуйте позже",
    status: "Состояние",
  },
  en: {
    title: "Purchase confirmation",
    merchant: "Merchant",
    amount: "Amount",
    order: "Order",
    until: "Valid until",
    instrument: "Payment method",
    CARD: "Card",
    SBP: "Faster Payments (SBP)",
    code: "Code from your bank",
    approve: "Confirm",
    reject: "Decline",
    approved: "Purchase confirmed. The agent will complete the payment with the merchant.",
    rejected: "Purchase declined.",
    notPending: "The request has already been processed or has expired",
    notFound: "Request not found",
    codeRejected: "The code was not accepted. Get a new code from your bank.",
    badForm: "Choose a payment method and a decision",
    unavailable: "Service temporarily unavailable, please try again later",
    status: "Status",
  },
} as const;

const COLOR = /^#[0-9a-fA-F]{6}$/;
const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src https:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const esc = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/**
 * Сумма для человека из минимальных единиц и валюты (правило совместимости 2). Число знаков — по CLDR (`Intl`): для RUB
 * совпадает с ISO 4217, у части валют расходится — таблица знаков ISO 4217 появится вместе с ними. Неизвестная валюта —
 * исключение (вызывающий отвечает страницей 503).
 */
function money(amount: number, currency: string, lang: UpkLang): string {
  const f = new Intl.NumberFormat(lang === "ru" ? "ru-RU" : "en-GB", { style: "currency", currency });
  return f.format(amount / 10 ** (f.resolvedOptions().maximumFractionDigits ?? 2));
}

/** Проверка настройки при создании: неверный бренд — отказ запуска эмулятора, а не страница с чужим кодом. */
function checkSettings(s: UpkPageSettings): UpkPageSettings {
  if (s.lang !== "ru" && s.lang !== "en") throw new Error(`страница УПК: язык ${String(s.lang)} — только ru или en`);
  if (typeof s.brand.name !== "string" || s.brand.name === "" || s.brand.name.length > 64) throw new Error("страница УПК: название бренда 1–64 знака");
  if (!COLOR.test(s.brand.color)) throw new Error("страница УПК: цвет бренда — #rrggbb");
  if (s.brand.logo_url !== undefined && !/^https:\/\/[^\s"'<>]+$/.test(s.brand.logo_url)) throw new Error("страница УПК: логотип — ссылка https://");
  return s;
}

export function createUpkPage(deps: UpkPageDeps): FastifyInstance {
  const settings = checkSettings(deps.settings ?? UPK_DEFAULT_SETTINGS);
  const instruments: readonly ConfirmationInstrument[] = deps.sbpEnabled ? ["CARD", "SBP"] : ["CARD"];
  const app = Fastify({ logger: false });
  // Форма браузера — application/x-www-form-urlencoded; разбор без новой зависимости.
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string", bodyLimit: 4096 }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });
  const langOf = (q: unknown): UpkLang => (q === "ru" || q === "en" ? q : settings.lang);

  const page = (reply: FastifyReply, code: number, lang: UpkLang, body: string) => {
    const t = TEXT[lang];
    const b = settings.brand;
    const other: UpkLang = lang === "ru" ? "en" : "ru";
    return reply
      .code(code)
      .header("content-type", "text/html; charset=utf-8")
      .header("cache-control", "no-store")
      .header("referrer-policy", "no-referrer")
      // Страница не встраивается во фрейм (clickjacking: человек жмёт «Подтвердить», думая, что делает другое) и шлёт
      // форму только себе (РП51 «Дополнения» п. 8).
      .header("x-frame-options", "DENY")
      .header("content-security-policy", CSP)
      .header("x-content-type-options", "nosniff")
      .send(
        `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
          `<title>${esc(t.title)} — ${esc(b.name)}</title>` +
          `<style>body{font-family:system-ui,sans-serif;margin:0;background:#fff;color:#1b1b1b}header{background:${b.color};color:#fff;padding:12px 16px;display:flex;gap:12px;align-items:center}` +
          `main{max-width:480px;margin:0 auto;padding:16px}dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px}dt{color:#555}button{background:${b.color};color:#fff;border:0;padding:10px 16px;margin-right:8px}` +
          `header img{height:28px}header a{color:#fff;margin-left:auto}</style></head><body>` +
          `<header>${b.logo_url ? `<img src="${esc(b.logo_url)}" alt="">` : ""}<strong data-brand>${esc(b.name)}</strong>` +
          `<a href="?lang=${other}" data-lang-switch>${other.toUpperCase()}</a></header><main><h1>${esc(t.title)}</h1>${body}</main></body></html>`,
      );
  };
  const message = (reply: FastifyReply, code: number, lang: UpkLang, text: string, status?: string) =>
    page(reply, code, lang, `<p data-result>${esc(text)}</p>${status ? `<p>${esc(TEXT[lang].status)}: <span data-status>${esc(status)}</span></p>` : ""}`);

  app.get<{ Params: { id: string }; Querystring: { lang?: string } }>("/c/:id", async (req, reply) => {
    const lang = langOf(req.query.lang);
    const t = TEXT[lang];
    const id = req.params.id;
    let r: ConfirmationRecord | undefined;
    try {
      r = CONFIRMATION_ID.test(id) ? await deps.confirmations.get(id) : undefined;
    } catch {
      return message(reply, 503, lang, t.unavailable);
    }
    if (!r) return message(reply, 404, lang, t.notFound);
    let amount: string;
    try {
      amount = money(r.amount, r.currency, lang);
    } catch {
      return message(reply, 503, lang, t.unavailable);
    }
    const summary =
      `<dl><dt>${esc(t.merchant)}</dt><dd data-merchant>${esc(r.merchant_id)}</dd>` +
      `<dt>${esc(t.amount)}</dt><dd data-amount>${esc(amount)}</dd>` +
      `<dt>${esc(t.order)}</dt><dd data-order>${esc(r.order_ref)}</dd>` +
      `<dt>${esc(t.until)}</dt><dd data-expires>${esc(r.expires_at)}</dd></dl>`;
    if (r.status !== "PENDING" || !(deps.now().toISOString() < r.expires_at)) {
      return page(reply, 409, lang, `${summary}<p data-result>${esc(t.notPending)}</p>`);
    }
    const radios = instruments
      .map((i, n) => `<label><input type="radio" name="instrument" value="${i}"${n === 0 ? " checked" : ""}> ${esc(t[i])}</label><br>`)
      .join("");
    return page(
      reply,
      200,
      lang,
      `${summary}<form method="post"><input type="hidden" name="lang" value="${lang}"><fieldset><legend>${esc(t.instrument)}</legend>${radios}</fieldset>` +
        `<p><label>${esc(t.code)} <input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required></label></p>` +
        `<button name="decision" value="APPROVE">${esc(t.approve)}</button><button name="decision" value="REJECT">${esc(t.reject)}</button></form>`,
    );
  });

  // Решение человека: форма → запрос П6 (в ожидании) → код (одноразовый, до ПИ-8) → подпись UPK → ПИ-8. Неверная форма и
  // инструмент вне настройки — отказ до кода (код не сгорает); неверный или сгоревший код — один ответ, без ПИ-8.
  app.post<{ Params: { id: string } }>("/c/:id", async (req, reply) => {
    const form = (req.body ?? {}) as Record<string, unknown>;
    const lang = langOf(form.lang);
    const t = TEXT[lang];
    const id = req.params.id;
    const decision = form.decision;
    const instrument = form.instrument;
    const code = form.code;
    if (
      (decision !== "APPROVE" && decision !== "REJECT") ||
      typeof instrument !== "string" ||
      !(instruments as readonly string[]).includes(instrument) ||
      typeof code !== "string" ||
      code.length > 64
    ) {
      return message(reply, 400, lang, t.badForm);
    }
    let r: ConfirmationRecord | undefined;
    try {
      r = CONFIRMATION_ID.test(id) ? await deps.confirmations.get(id) : undefined;
    } catch {
      return message(reply, 503, lang, t.unavailable);
    }
    if (!r) return message(reply, 404, lang, t.notFound);
    const at = deps.now().toISOString();
    if (r.status !== "PENDING" || !(at < r.expires_at)) return message(reply, 409, lang, t.notPending);
    if (!deps.codes.redeem(id, code, at)) return message(reply, 403, lang, t.codeRejected);
    const record = {
      participant_code: deps.upk.participant_code,
      kid: deps.upk.trustedKey.kid,
      confirmation_id: id,
      decision,
      totals_hash: totalsHash(r),
      decided_at: at,
      instrument_chosen: instrument as ConfirmationInstrument,
    } as const;
    const { confirmation_id: _id, ...body } = { ...record, signature: deps.upk.signConfirmation(record) };
    void _id;
    let res: { statusCode: number; body: unknown };
    try {
      res = await deps.submit(id, body);
    } catch {
      return message(reply, 503, lang, t.unavailable);
    }
    if (res.statusCode === 200) {
      const status = (res.body as { status?: string }).status ?? "";
      return message(reply, 200, lang, status === "REJECTED" ? t.rejected : t.approved, status);
    }
    if (res.statusCode === 409) return message(reply, 409, lang, t.notPending, (res.body as { status?: string }).status);
    return message(reply, res.statusCode >= 500 ? 503 : 502, lang, t.unavailable);
  });

  return app;
}
