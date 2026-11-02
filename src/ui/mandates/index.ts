// Экран мандатов — эталонный модуль банка (UI-К2; план «Россия» ред. 4, ROADMAP В1): клиент банка видит и подписывает
// мандаты агентов, отзывает их и все полномочия одним действием; дальше — подтверждение покупки, агенты, история (ч. 2–3).
// Встраивается в приложение банка как веб-вид (WebView верхнего уровня); в песочнице — интерфейс эмулятора эмитента
// (`src/env/issuer/screen.ts`). Экран сам ничего не решает и не пишет: данные и действия — через порт банка, действия
// банк подписывает своим ключом и шлёт по ПИ-8 (инвариант 6). Язык и бренд — настройка экрана (правило совместимости 3);
// номера карты нет (инвариант 1).
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest, type FastifyServerOptions } from "fastify";
import { withRequestSerializer } from "../../http/request-log.js";
import { MANDATE_ID } from "../../consent/model.js";
import { checkUiSettings, esc, formParser, htmlHeaders, langOf, money, pageHtml, type UiLang, type UiSettings } from "../shared/index.js";
import type { MandatesScreenPort, ScreenMandate } from "./port.js";
import { CLEAR_COOKIE, ScreenSessions, sessionCookie, setCookie, type ScreenSession, type ScreenSessionTtl } from "./session.js";
import { TEXT } from "./text.js";

export const component = "ui/mandates";

export const MANDATES_DEFAULT_SETTINGS: UiSettings = { lang: "ru", brand: { name: "Банк стенда", color: "#2e7d32" } };

export interface MandatesScreenDeps {
  readonly port: MandatesScreenPort;
  readonly settings?: UiSettings;
  readonly ttl: ScreenSessionTtl;
  readonly now: () => Date;
  /**
   * Журнал процесса (как у сервера Платформы, РП61 п. 3, РП63 п. 13): запрос — метод и шаблон маршрута, без пути, токена
   * ссылки и cookie. Не задан — журнала нет.
   */
  readonly logger?: FastifyServerOptions["logger"];
}

export interface MandatesScreen {
  readonly app: FastifyInstance;
  /** Путь одноразовой ссылки входа (`/login/{token}`) для клиента, которого банк уже опознал. */
  loginPath(principal_ref: string): string;
}

type Text = (typeof TEXT)[UiLang];

/** Сбой порта или неизвестная валюта — исключение; вызывающий отвечает 503 без кнопок. */
class Unavailable extends Error {}

export function createMandatesScreen(deps: MandatesScreenDeps): MandatesScreen {
  const settings = checkUiSettings(deps.settings ?? MANDATES_DEFAULT_SETTINGS, "экран мандатов");
  const sessions = new ScreenSessions(deps.ttl, deps.now);
  const port = deps.port;
  const app = Fastify({ logger: withRequestSerializer(deps.logger ?? false) });
  formParser(app);

  const page = (reply: FastifyReply, code: number, lang: UiLang, title: string, body: string) =>
    htmlHeaders(reply, code).send(pageHtml({ lang, title, brand: settings.brand, body }));
  const message = (reply: FastifyReply, code: number, lang: UiLang, text: string, extra = "") =>
    page(reply, code, lang, TEXT[lang].title, `<p data-result>${esc(text)}</p>${extra}`);
  const queryLang = (req: FastifyRequest) => langOf((req.query as { lang?: unknown } | undefined)?.lang, settings.lang);
  const backLink = (lang: UiLang) => `<p><a href="/?lang=${lang}" data-back>${esc(TEXT[lang].back)}</a></p>`;

  /** Сессия запроса по cookie; нет — undefined (вызывающий отвечает 401). */
  const session = (req: FastifyRequest): { sid: string; s: ScreenSession } | undefined => {
    const sid = sessionCookie(req.headers.cookie);
    const s = sessions.get(sid);
    return s && sid ? { sid, s } : undefined;
  };

  /** Сумма для человека; неизвестная валюта — Unavailable. */
  const sum = (amount: number, currency: string, lang: UiLang): string => {
    try {
      return money(amount, currency, lang);
    } catch {
      throw new Unavailable();
    }
  };

  /** Ждёт подписи и не истёк по часам экрана — только тогда есть кнопки (неизвестный статус — без действий). */
  const pending = (m: ScreenMandate) => m.status === "PENDING_SIGNATURE" && deps.now().toISOString() < m.valid_to;

  const statusText = (t: Text, s: string) => t.statuses[s] ?? s;

  app.get<{ Params: { token: string } }>("/login/:token", async (req, reply) => {
    const lang = queryLang(req);
    const sid = sessions.redeemLogin(req.params.token);
    if (!sid) return message(reply, 401, lang, TEXT[lang].linkInvalid);
    return reply.code(303).header("set-cookie", setCookie(sid, deps.ttl.session_ttl_sec)).header("cache-control", "no-store").header("location", `/?lang=${lang}`).send();
  });

  // Список мандатов клиента: ждущие подписи — первыми.
  app.get("/", async (req, reply) => {
    const lang = queryLang(req);
    const t = TEXT[lang];
    const cur = session(req);
    if (!cur) return message(reply, 401, lang, t.signIn);
    let rows: string;
    try {
      const list = await port.mandates(cur.s.principal_ref);
      const sorted = [...list.filter(pending), ...list.filter((m) => !pending(m))];
      rows =
        sorted.length === 0
          ? `<p data-empty>${esc(t.empty)}</p>`
          : `<ul data-mandates>${sorted
              .map(
                (m) =>
                  `<li data-mandate="${esc(m.id)}"><a href="/m/${esc(m.id)}?lang=${lang}">${esc(t.types[m.type] ?? m.type)} · ${esc(m.agent_code)}</a>` +
                  ` — <span data-status>${esc(statusText(t, m.status))}</span> · ${esc(sum(m.amount_limit, m.currency, lang))}</li>`,
              )
              .join("")}</ul>`;
    } catch {
      return message(reply, 503, lang, t.unavailable);
    }
    return page(reply, 200, lang, t.title, rows + logoutForm(lang, cur.s.csrf));
  });

  // Мандат: значения из записи Платформы, кнопки — только у ждущего подписи.
  app.get<{ Params: { id: string } }>("/m/:id", async (req, reply) => {
    const lang = queryLang(req);
    const t = TEXT[lang];
    const cur = session(req);
    if (!cur) return message(reply, 401, lang, t.signIn);
    let body: string;
    try {
      const m = MANDATE_ID.test(req.params.id) ? await port.mandate(cur.s.principal_ref, req.params.id) : undefined;
      if (!m) return message(reply, 404, lang, t.notFound, backLink(lang));
      body = mandateHtml(m, t, lang, sum, statusText);
      if (pending(m)) {
        body +=
          `<form method="post" action="/m/${esc(m.id)}/decision"><input type="hidden" name="lang" value="${lang}">` +
          `<input type="hidden" name="csrf" value="${esc(cur.s.csrf)}">` +
          `<button name="decision" value="SIGN" data-sign>${esc(t.sign)}</button><button name="decision" value="REJECT" data-reject>${esc(t.reject)}</button></form>`;
      }
    } catch {
      return message(reply, 503, lang, t.unavailable, backLink(lang));
    }
    return page(reply, 200, lang, t.mandate, body + backLink(lang));
  });

  // Решение клиента: сессия → CSRF → форма → мандат клиента → подпись банка и ПИ-8 (порт).
  app.post<{ Params: { id: string } }>("/m/:id/decision", async (req, reply) => {
    const form = (req.body ?? {}) as Record<string, unknown>;
    const lang = langOf(form.lang, settings.lang);
    const t = TEXT[lang];
    const cur = session(req);
    if (!cur) return message(reply, 401, lang, t.signIn);
    if (!ScreenSessions.csrfOk(cur.s, form.csrf)) return message(reply, 403, lang, t.formExpired, backLink(lang));
    const decision = form.decision;
    if (decision !== "SIGN" && decision !== "REJECT") return message(reply, 400, lang, t.badForm, backLink(lang));
    if (!MANDATE_ID.test(req.params.id)) return message(reply, 404, lang, t.notFound, backLink(lang));
    let r: Awaited<ReturnType<MandatesScreenPort["decide"]>>;
    try {
      r = await port.decide(cur.s.principal_ref, req.params.id, decision);
    } catch {
      return message(reply, 503, lang, t.unavailable, backLink(lang));
    }
    const status = (s: string | undefined) => (s ? `<p>${esc(t.status)}: <span data-status>${esc(statusText(t, s))}</span></p>` : "");
    switch (r.kind) {
      case "DONE":
        return message(reply, 200, lang, r.status === "REJECTED" ? t.rejected : t.signed, status(r.status) + backLink(lang));
      case "QUALIFIED_SIGNATURE_REQUIRED":
        return message(reply, 422, lang, t.qualified, backLink(lang));
      case "NOT_PENDING":
        return message(reply, 409, lang, t.notPending, status(r.status) + backLink(lang));
      case "NOT_FOUND":
        return message(reply, 404, lang, t.notFound, backLink(lang));
    }
  });

  app.post("/logout", async (req, reply) => {
    const form = (req.body ?? {}) as Record<string, unknown>;
    const lang = langOf(form.lang, settings.lang);
    const cur = session(req);
    if (!cur) return message(reply, 401, lang, TEXT[lang].signIn);
    if (!ScreenSessions.csrfOk(cur.s, form.csrf)) return message(reply, 403, lang, TEXT[lang].formExpired);
    sessions.close(cur.sid);
    reply.header("set-cookie", CLEAR_COOKIE);
    return message(reply, 200, lang, TEXT[lang].signedOut);
  });

  return { app, loginPath: (principal_ref) => `/login/${sessions.issueLogin(principal_ref)}` };
}

function mandateHtml(
  m: ScreenMandate,
  t: Text,
  lang: UiLang,
  sum: (amount: number, currency: string, lang: UiLang) => string,
  statusText: (t: Text, s: string) => string,
): string {
  const row = (name: string, attr: string, value: string) => `<dt>${esc(name)}</dt><dd data-${attr}>${value}</dd>`;
  let dl =
    row(t.agent, "agent", esc(m.agent_code)) +
    row(t.type, "type", esc(t.types[m.type] ?? m.type)) +
    row(t.status, "status", esc(statusText(t, m.status))) +
    row(t.limit, "limit", esc(sum(m.amount_limit, m.currency, lang))) +
    row(t.until, "until", esc(m.valid_to)) +
    row(t.merchants, "merchants", esc(m.merchant_scope.join(", "))) +
    row(t.subject, "subject", esc(m.subject));
  if (m.parent_id) dl += row(t.parent, "parent", esc(m.parent_id));
  let cart = "";
  if (m.cart?.items && m.cart.items.length > 0) {
    cart =
      `<h2>${esc(t.cart)}</h2><ul data-cart>` +
      m.cart.items
        .map((i) => `<li>${esc(i.sku ?? "—")} × ${esc(i.qty === undefined ? "—" : String(i.qty))} — ${esc(i.price === undefined ? "—" : sum(i.price, m.currency, lang))}</li>`)
        .join("") +
      `</ul>` +
      (m.cart.total !== undefined ? `<p data-total>${esc(t.total)}: ${esc(sum(m.cart.total, m.currency, lang))}</p>` : "");
  }
  return `<dl>${dl}</dl>${cart}<p><small>${esc(t.hash)}: <code data-hash>${esc(m.hash)}</code></small></p>`;
}

function logoutForm(lang: UiLang, csrf: string): string {
  return (
    `<form method="post" action="/logout"><input type="hidden" name="lang" value="${lang}">` +
    `<input type="hidden" name="csrf" value="${esc(csrf)}"><button data-logout>${esc(TEXT[lang].signOut)}</button></form>`
  );
}
