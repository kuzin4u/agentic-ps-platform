// Человеческий вид витрин стенда (РП58 дополнение З12): GET /shops — список магазинов карточками, GET /shops/{id} — каталог
// карточками товаров; язык — ?lang=ru|en. Только стенд: регистрирует createMerchants на сервере витрин; buildMerchantsServer,
// src/main.ts и buildServer страниц не знают (страж — tests/unit/stand-boundary.test.ts). JSON-маршруты /v1/… не меняются.
// Страница — вид набора витрин стенда, а не ответ витрины: сбои тестов и демо-стенда не применяются (п. 7).
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { byShopId, catalogView, zoneOf, type Shop, type ShopItem } from "../env/merchants/shops.js";
import { checkUiSettings, esc, htmlHeaders, langOf, money, pageHtml, type UiLang, type UiSettings } from "../ui/shared/index.js";
import { SHOWCASE_TEXT } from "./showcase-text.js";

/** Настройка по умолчанию (п. 8): логотипа нет — внешних ресурсов на странице нет. */
export const SHOWCASE_DEFAULT_SETTINGS: UiSettings = { lang: "ru", brand: { name: "Эмулятор продавцов", color: "#5d4037" } };

/** Проверка настройки при createMerchants: неверный язык или бренд — исключение, а не страница с чужим кодом. */
export const showcaseSettings = (s: UiSettings | undefined): UiSettings => checkUiSettings(s ?? SHOWCASE_DEFAULT_SETTINGS, "страница витрин");

export interface ShowcaseDeps {
  /** Набор витрин сервера (тот же, что у /v1/shops). */
  readonly shops: readonly Shop[];
  /** Уже проверенная настройка (`showcaseSettings`). */
  readonly settings: UiSettings;
  /** Часы стенда — для `catalogView` (цена человека). */
  readonly now: () => Date;
}

type Text = (typeof SHOWCASE_TEXT)[UiLang];

/** Карточки — свои стили в теле страницы (CSP: `style-src 'unsafe-inline'`); ничего внешнего. */
const STYLE =
  "<style>.cards{list-style:none;padding:0}.card{border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0}" +
  ".card h2{font-size:1.1em;margin:0 0 6px}.lead{color:#555}</style>";

/** Цена для человека (п. 3): минимальные единицы и валюта; нет цены или валюты — «цена не указана». */
function priceText(item: ShopItem, now: Date, lang: UiLang, t: Text): string {
  const view = catalogView(item, false, now);
  return typeof view.price === "number" && typeof view.currency === "string" ? money(view.price, view.currency, lang) : t.priceMissing;
}

const stockText = (item: ShopItem, t: Text): string =>
  item.in_stock === true ? t.inStock : item.in_stock === false ? t.outOfStock : t.stockUnknown;

export function registerShowcase(app: FastifyInstance, deps: ShowcaseDeps): void {
  const { settings } = deps;
  const shops = [...deps.shops].sort(byShopId);
  const byId = new Map(shops.map((s) => [s.id, s]));

  const queryLang = (req: FastifyRequest): UiLang => langOf((req.query as { lang?: unknown } | undefined)?.lang, settings.lang);
  const page = (reply: FastifyReply, code: number, lang: UiLang, title: string, body: string) =>
    htmlHeaders(reply, code).send(pageHtml({ lang, title, brand: settings.brand, body: `${STYLE}${body}` }));
  const backLink = (lang: UiLang) => `<p><a href="/shops?lang=${lang}" data-back>${esc(SHOWCASE_TEXT[lang].back)}</a></p>`;

  // Маршруты — в своей области после плагина лимита сервера витрин: лимит частоты общий с /v1 (п. 6).
  void app.register(async (scope) => {
    // Отказ лимита и сбой — страница для человека, а не {code}: Retry-After лимит ставит до выброса.
    scope.setErrorHandler((err, req, reply) => {
      const lang = queryLang(req);
      const t = SHOWCASE_TEXT[lang];
      const limited = (err as { statusCode?: number }).statusCode === 429;
      return page(reply, limited ? 429 : 503, lang, t.title, `<p data-result>${esc(limited ? t.tooMany : t.unavailable)}</p>`);
    });

    scope.get("/shops", async (req, reply) => {
      const lang = queryLang(req);
      const t = SHOWCASE_TEXT[lang];
      const cards = shops
        .map((s) => {
          const zone = zoneOf(s);
          return (
            `<li class="card" data-shop="${esc(s.id)}">` +
            `<h2><a href="/shops/${esc(encodeURIComponent(s.id))}?lang=${lang}">${esc(s.name)}</a></h2>` +
            `<dl><dt>${esc(t.shopId)}</dt><dd data-id>${esc(s.id)}</dd>` +
            `<dt>${esc(t.sells)}</dt><dd data-sells>${esc(s.category)}</dd>` +
            `<dt>${esc(t.items)}</dt><dd data-count>${s.items.length}</dd>` +
            `<dt>${esc(t.zone)}</dt><dd data-zone="${zone}">${esc(t.zones[zone])}</dd></dl></li>`
          );
        })
        .join("");
      return page(reply, 200, lang, t.title, `<p class="lead">${esc(t.lead)}</p><ul class="cards">${cards}</ul>`);
    });

    scope.get<{ Params: { id: string } }>("/shops/:id", async (req, reply) => {
      const lang = queryLang(req);
      const t = SHOWCASE_TEXT[lang];
      const shop = byId.get(req.params.id);
      if (!shop) return page(reply, 404, lang, t.title, `<p data-result>${esc(t.notFound)}</p>${backLink(lang)}`);
      const now = deps.now();
      const cards = shop.items
        .map(
          (i) =>
            `<li class="card" data-item="${esc(i.sku)}"><h2>${esc(i.title)}</h2>` +
            `<dl><dt>${esc(t.price)}</dt><dd data-price>${esc(priceText(i, now, lang, t))}</dd>` +
            `<dt>${esc(t.stock)}</dt><dd data-stock>${esc(stockText(i, t))}</dd></dl></li>`,
        )
        .join("");
      const zone = zoneOf(shop);
      const head =
        `<p data-shop="${esc(shop.id)}">${esc(shop.id)} · ${esc(shop.category)} · ` +
        `<span data-zone="${zone}">${esc(t.zones[zone])}</span></p>`;
      const list = shop.items.length > 0 ? `<ul class="cards">${cards}</ul>` : `<p data-empty>${esc(t.empty)}</p>`;
      return page(reply, 200, lang, shop.name, `${head}${list}${backLink(lang)}`);
    });
  });
}
