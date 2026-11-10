// Общее для экранов человека (UI-К2; правило совместимости 3): язык и бренд — настройка экрана, в ADP, ПАО и
// канонической модели текстов и бренда нет. Здесь — проверка настройки, экранирование, сумма из минимальных единиц и
// валюты (правило совместимости 2), заголовки безопасности и оболочка страницы. Страница УПК (`src/env/upk/page.ts`)
// пока держит свою копию — перевод на этот модуль в STATUS «Открыто» (решение владельца 02.11, UI-К2 ч. 1).
import type { FastifyInstance, FastifyReply } from "fastify";
import { parseRfc3339 } from "../../consent/model.js";

export type UiLang = "ru" | "en";
export const UI_LANGS: readonly UiLang[] = ["ru", "en"];

/** Бренд: название, цвет (#rrggbb), логотип по ссылке https://. */
export interface UiBrand {
  readonly name: string;
  readonly color: string;
  readonly logo_url?: string;
}

export interface UiSettings {
  /** Язык по умолчанию; переключение — `?lang=` или поле формы `lang`. */
  readonly lang: UiLang;
  readonly brand: UiBrand;
  /** Пояс времени для человека (имя IANA, например `Europe/Moscow`); не задан — пояс процесса (РП36 «Нюанс UI-К2 — З9» п. 1). */
  readonly time_zone?: string;
}

const COLOR = /^#[0-9a-fA-F]{6}$/;
const LOGO = /^https:\/\/[^\s"'<>]+$/;

/** Проверка настройки при создании экрана: неверный язык или бренд — отказ запуска, а не страница с чужим кодом. */
export function checkUiSettings(s: UiSettings, what: string): UiSettings {
  if (!UI_LANGS.includes(s.lang)) throw new Error(`${what}: язык ${String(s.lang)} — только ru или en`);
  if (typeof s.brand?.name !== "string" || s.brand.name === "" || s.brand.name.length > 64) throw new Error(`${what}: название бренда 1–64 знака`);
  if (typeof s.brand.color !== "string" || !COLOR.test(s.brand.color)) throw new Error(`${what}: цвет бренда — #rrggbb`);
  if (s.brand.logo_url !== undefined && (typeof s.brand.logo_url !== "string" || !LOGO.test(s.brand.logo_url))) {
    throw new Error(`${what}: логотип — ссылка https://`);
  }
  if (s.time_zone !== undefined) {
    let ok = typeof s.time_zone === "string" && s.time_zone !== "" && s.time_zone.length <= 64;
    try {
      if (ok) new Intl.DateTimeFormat("en", { timeZone: s.time_zone });
    } catch {
      ok = false;
    }
    if (!ok) throw new Error(`${what}: пояс времени — имя IANA`);
  }
  return s;
}

/**
 * Время для человека (РП36 «Нюанс UI-К2 — З9» п. 1): по языку страницы — `ru` «ДД.ММ.ГГГГ, ЧЧ:ММ», `en` «DD/MM/YYYY, HH:MM»,
 * в поясе экрана; не задан — пояс процесса при создании. Машинное значение — в `<time datetime>`. Неразборчивая строка
 * (не RFC 3339) — как есть, экранированной: экран только показывает и ничего не решает.
 */
export function uiTime(time_zone: string | undefined): (iso: string, lang: UiLang) => string {
  const timeZone = time_zone ?? new Intl.DateTimeFormat().resolvedOptions().timeZone;
  const opts = { timeZone, day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" } as const;
  const fmt: Record<UiLang, Intl.DateTimeFormat> = { ru: new Intl.DateTimeFormat("ru-RU", opts), en: new Intl.DateTimeFormat("en-GB", opts) };
  return (iso, lang) => {
    const ms = parseRfc3339(iso);
    return Number.isNaN(ms) ? `<time>${esc(iso)}</time>` : `<time datetime="${esc(iso)}">${esc(fmt[lang].format(ms))}</time>`;
  };
}

/** Язык из запроса: только ru / en, иначе — язык настройки. */
export const langOf = (q: unknown, fallback: UiLang): UiLang => (q === "ru" || q === "en" ? q : fallback);

export const esc = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/**
 * Сумма для человека из минимальных единиц и валюты (правило совместимости 2). Число знаков — по CLDR (`Intl`): для RUB
 * совпадает с ISO 4217. Неизвестная валюта — исключение (вызывающий отвечает страницей 503).
 */
export function money(amount: number, currency: string, lang: UiLang): string {
  const f = new Intl.NumberFormat(lang === "ru" ? "ru-RU" : "en-GB", { style: "currency", currency });
  return f.format(amount / 10 ** (f.resolvedOptions().maximumFractionDigits ?? 2));
}

/**
 * Страница не встраивается во фрейм (clickjacking: человек жмёт «Подписать», думая, что делает другое), шлёт формы
 * только себе, скриптов нет. Во встраивании в приложение банка — WebView верхнего уровня, не фрейм.
 */
export const UI_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src https:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/** Заголовки безопасности и HTML без кэша. */
export function htmlHeaders(reply: FastifyReply, code: number): FastifyReply {
  return reply
    .code(code)
    .header("content-type", "text/html; charset=utf-8")
    .header("cache-control", "no-store")
    .header("referrer-policy", "no-referrer")
    .header("x-frame-options", "DENY")
    .header("content-security-policy", UI_CSP)
    .header("x-content-type-options", "nosniff");
}

/**
 * Оболочка страницы: шапка с брендом и переключателем языка; `body` — уже экранированный HTML. `refresh_sec` — мета-обновление
 * страницы без скриптов (РП36 «Нюанс UI-К2 — З9» п. 2: CSP мета-обновление не регулирует); целое проверяет вызывающий.
 */
export function pageHtml(o: {
  readonly lang: UiLang;
  readonly title: string;
  readonly brand: UiBrand;
  readonly body: string;
  readonly refresh_sec?: number;
}): string {
  const b = o.brand;
  const other: UiLang = o.lang === "ru" ? "en" : "ru";
  const refresh = o.refresh_sec === undefined ? "" : `<meta http-equiv="refresh" content="${Math.trunc(o.refresh_sec)}">`;
  return (
    `<!doctype html><html lang="${o.lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${refresh}` +
    `<title>${esc(o.title)} — ${esc(b.name)}</title>` +
    `<style>body{font-family:system-ui,sans-serif;margin:0;background:#fff;color:#1b1b1b}header{background:${b.color};color:#fff;padding:12px 16px;display:flex;gap:12px;align-items:center}` +
    `main{max-width:560px;margin:0 auto;padding:16px}dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px}dt{color:#555}button{background:${b.color};color:#fff;border:0;padding:10px 16px;margin-right:8px}` +
    `header img{height:28px}header a{color:#fff;margin-left:auto}</style></head><body>` +
    `<header>${b.logo_url ? `<img src="${esc(b.logo_url)}" alt="">` : ""}<strong data-brand>${esc(b.name)}</strong>` +
    `<a href="?lang=${other}" data-lang-switch>${other.toUpperCase()}</a></header><main><h1>${esc(o.title)}</h1>${o.body}</main></body></html>`
  );
}

/** Разбор формы браузера (application/x-www-form-urlencoded) без новой зависимости; тело — не больше 4 КиБ. */
export function formParser(app: FastifyInstance): void {
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string", bodyLimit: 4096 }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });
}
