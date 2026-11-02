// Экран мандатов — эталонный модуль банка (UI-К2; план «Россия» ред. 4, ROADMAP В1): клиент банка видит и подписывает
// мандаты агентов, отзывает их и все полномочия одним действием; дальше — подтверждение покупки, агенты, история (ч. 2–3).
// Встраивается в приложение банка как веб-вид (WebView верхнего уровня); в песочнице — интерфейс эмулятора эмитента
// (`src/env/issuer/screen.ts`). Экран сам ничего не решает и не пишет: данные и действия — через порт банка, действия
// банк подписывает своим ключом и шлёт по ПИ-8 (инвариант 6). Язык и бренд — настройка экрана (правило совместимости 3);
// номера карты нет (инвариант 1).
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import type { FastifyServerOptions } from "fastify";
import { withRequestSerializer } from "../../http/request-log.js";
import { checkUiSettings, esc, formParser, htmlHeaders, langOf, pageHtml, type UiLang, type UiSettings } from "../shared/index.js";
import { CLEAR_COOKIE, ScreenSessions, sessionCookie, setCookie, type ScreenSession, type ScreenSessionTtl } from "./session.js";
import { TEXT } from "./text.js";

export const component = "ui/mandates";

export const MANDATES_DEFAULT_SETTINGS: UiSettings = { lang: "ru", brand: { name: "Банк стенда", color: "#2e7d32" } };

export interface MandatesScreenDeps {
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

export function createMandatesScreen(deps: MandatesScreenDeps): MandatesScreen {
  const settings = checkUiSettings(deps.settings ?? MANDATES_DEFAULT_SETTINGS, "экран мандатов");
  const sessions = new ScreenSessions(deps.ttl, deps.now);
  const app = Fastify({ logger: withRequestSerializer(deps.logger ?? false) });
  formParser(app);

  const page = (reply: FastifyReply, code: number, lang: UiLang, title: string, body: string) =>
    htmlHeaders(reply, code).send(pageHtml({ lang, title, brand: settings.brand, body }));
  const message = (reply: FastifyReply, code: number, lang: UiLang, text: string) =>
    page(reply, code, lang, TEXT[lang].title, `<p data-result>${esc(text)}</p>`);
  const queryLang = (req: FastifyRequest) => langOf((req.query as { lang?: unknown } | undefined)?.lang, settings.lang);

  /** Сессия запроса или страница 401 (ответ уже отправлен — undefined). */
  const session = (req: FastifyRequest): { sid: string; s: ScreenSession } | undefined => {
    const sid = sessionCookie(req.headers.cookie);
    const s = sessions.get(sid);
    return s && sid ? { sid, s } : undefined;
  };

  app.get<{ Params: { token: string } }>("/login/:token", async (req, reply) => {
    const lang = queryLang(req);
    const sid = sessions.redeemLogin(req.params.token);
    if (!sid) return message(reply, 401, lang, TEXT[lang].linkInvalid);
    return reply.code(303).header("set-cookie", setCookie(sid, deps.ttl.session_ttl_sec)).header("cache-control", "no-store").header("location", `/?lang=${lang}`).send();
  });

  app.get("/", async (req, reply) => {
    const lang = queryLang(req);
    const t = TEXT[lang];
    const cur = session(req);
    if (!cur) return message(reply, 401, lang, t.signIn);
    return page(reply, 200, lang, t.title, logoutForm(lang, cur.s.csrf));
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

function logoutForm(lang: UiLang, csrf: string): string {
  return (
    `<form method="post" action="/logout"><input type="hidden" name="lang" value="${lang}">` +
    `<input type="hidden" name="csrf" value="${esc(csrf)}"><button data-logout>${esc(TEXT[lang].signOut)}</button></form>`
  );
}
