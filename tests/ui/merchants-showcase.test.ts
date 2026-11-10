// РП58 дополнение З12: человеческий вид витрин стенда — GET /shops (список) и GET /shops/{id} (каталог), ?lang=ru|en.
// Только стенд (createMerchants); JSON /v1/… не меняется; данные витрины — через esc, внешних ресурсов нет.
import { afterEach, describe, expect, it } from "vitest";
import { SHOPS, zoneOf, type Shop } from "../../src/env/merchants/shops.js";
import { createMerchants, createStand, type MerchantsStand } from "../../src/stand/index.js";
import { money, UI_CSP, type UiSettings } from "../../src/ui/shared/index.js";

let m: MerchantsStand | undefined;
afterEach(async () => {
  await m?.close();
  m = undefined;
});

function setup(o: { shops?: readonly Shop[]; merchants?: Parameters<typeof createMerchants>[1] } = {}): MerchantsStand {
  const s = createStand(o.shops ? { shops: o.shops } : {});
  m = createMerchants(s, o.merchants ?? {});
  return m;
}

const get = (mm: MerchantsStand, url: string) => mm.app.inject({ method: "GET", url });
const ids = (html: string, attr: string) => [...html.matchAll(new RegExp(`<li class="card" ${attr}="([^"]+)"`, "g"))].map((x) => x[1]);
/** Карточка по атрибуту — от открывающего <li> до </li>. */
const card = (html: string, attr: string, id: string): string => {
  const at = html.indexOf(`<li class="card" ${attr}="${id}"`);
  expect(at, `${attr}=${id}`).toBeGreaterThanOrEqual(0);
  return html.slice(at, html.indexOf("</li>", at));
};
const SORTED = [...SHOPS].map((s) => s.id).sort();

describe("З12: список витрин", () => {
  it("ru по умолчанию: карточка на витрину по порядку id — название, id, что продаёт, число товаров, контур, ссылка на каталог", async () => {
    const r = await get(setup(), "/shops");
    expect(r.statusCode).toBe(200);
    expect(r.headers["content-type"]).toBe("text/html; charset=utf-8");
    expect(r.body).toContain('<html lang="ru"');
    expect(r.body).toContain("<h1>Витрины продавцов</h1>");
    expect(ids(r.body, "data-shop")).toEqual(SORTED);
    for (const s of SHOPS) {
      const c = card(r.body, "data-shop", s.id);
      expect(c).toContain(`<a href="/shops/${s.id}?lang=ru">${s.name}</a>`);
      expect(c).toContain(`<dd data-id>${s.id}</dd>`);
      expect(c).toContain(`<dd data-sells>${s.category}</dd>`);
      expect(c).toContain(`<dd data-count>${s.items.length}</dd>`);
      expect(c).toContain(`<dd data-zone="${zoneOf(s)}">${zoneOf(s) === "CONTOUR" ? "в контуре" : "вне контура"}</dd>`);
    }
  });

  it("?lang=en — английский, переключатель на ru; неизвестный язык — язык настройки", async () => {
    const mm = setup();
    const en = await get(mm, "/shops?lang=en");
    expect(en.body).toContain('<html lang="en"');
    expect(en.body).toContain("<h1>Merchant shops</h1>");
    expect(en.body).toContain('<a href="?lang=ru" data-lang-switch>RU</a>');
    expect(card(en.body, "data-shop", "MKT-77")).toContain('<dd data-zone="OUTSIDE">outside the contour</dd>');
    expect(card(en.body, "data-shop", "SHOP-1042")).toContain('<a href="/shops/SHOP-1042?lang=en">');
    const de = await get(mm, "/shops?lang=de");
    expect(de.body).toContain('<html lang="ru"');
  });

  it("showcaseUi: язык и бренд настройки; неверная настройка — исключение при createMerchants", async () => {
    const ui: UiSettings = { lang: "en", brand: { name: "Shop emulator", color: "#123456" } };
    const r = await get(setup({ merchants: { showcaseUi: ui } }), "/shops");
    expect(r.body).toContain('<html lang="en"');
    expect(r.body).toContain('<strong data-brand>Shop emulator</strong>');
    const s = createStand();
    expect(() => createMerchants(s, { showcaseUi: { lang: "de" as "en", brand: ui.brand } })).toThrow(/страница витрин: язык/);
    expect(() => createMerchants(s, { showcaseUi: { lang: "ru", brand: { name: "x", color: "red" } } })).toThrow(/цвет бренда/);
  });
});

describe("З12: каталог витрины", () => {
  it("карточка товара — название, цена из минимальных единиц и валюты, наличие", async () => {
    const r = await get(setup(), "/shops/SHOP-1042");
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain("<h1>Масса Мадре</h1>");
    const shop = SHOPS.find((s) => s.id === "SHOP-1042")!;
    expect(ids(r.body, "data-item")).toEqual(shop.items.map((i) => i.sku));
    for (const i of shop.items) {
      const c = card(r.body, "data-item", i.sku);
      expect(c).toContain(`<h2>${i.title}</h2>`);
      expect(c).toContain(`<dd data-price>${money(i.price!, i.currency!, "ru")}</dd>`);
      expect(c).toContain("<dd data-stock>в наличии</dd>");
    }
    expect(r.body).toContain('<a href="/shops?lang=ru" data-back>К списку витрин</a>');
  });

  it("неполная витрина SHOP-5501: нет цены — «цена не указана», нет наличия — «наличие не указано»", async () => {
    const r = await get(setup(), "/shops/SHOP-5501");
    const noPrice = card(r.body, "data-item", "BRD-5501-01");
    expect(noPrice).toContain("<dd data-price>цена не указана</dd>");
    expect(noPrice).toContain("<dd data-stock>наличие не указано</dd>");
    expect(card(r.body, "data-item", "BRD-5501-02")).toContain(`<dd data-price>${money(9000, "RUB", "ru")}</dd>`);
    const en = await get(m!, "/shops/SHOP-5501?lang=en");
    expect(card(en.body, "data-item", "BRD-5501-01")).toContain("<dd data-price>price not given</dd>");
  });

  it("DUAL_PRICE SHOP-3303 — цена человека, не агента; SHOP-4401 — каталог показывается (вид набора, В3 (а))", async () => {
    const mm = setup();
    const dual = await get(mm, "/shops/SHOP-3303");
    expect(card(dual.body, "data-item", "BRD-3303-01")).toContain(`<dd data-price>${money(41000, "RUB", "ru")}</dd>`);
    expect(dual.body).not.toContain(money(36900, "RUB", "ru"));
    const r = await get(mm, "/shops/SHOP-4401");
    expect(r.statusCode).toBe(200);
    expect(ids(r.body, "data-item")).toEqual(["BRD-4401-01"]);
    // Путь агента не меняется: JSON-каталог без подписи по-прежнему отказывает.
    const json = await get(mm, "/v1/shops/SHOP-4401/catalog");
    expect([json.statusCode, json.json()]).toEqual([403, { code: "AGENT_UNIDENTIFIED" }]);
  });

  it("неизвестная витрина — страница 404 (HTML), не {code}", async () => {
    const r = await get(setup(), "/shops/SHOP-0000?lang=en");
    expect(r.statusCode).toBe(404);
    expect(r.headers["content-type"]).toBe("text/html; charset=utf-8");
    expect(r.body).toContain("<p data-result>Shop not found</p>");
  });
});

describe("З12: пометка учебных витрин (п. 4, В1 (а), В2 (а))", () => {
  /** Набор по умолчанию: витрина → ключ строки; прочие — без пометки. */
  const MARKED: Readonly<Record<string, string>> = {
    "SHOP-3301": "CONTRADICTORY",
    "SHOP-3302": "INJECTION",
    "SHOP-3303": "DUAL_PRICE",
    "SHOP-4401": "REJECTS_UNIDENTIFIED",
    "SHOP-5501": "INCOMPLETE",
    "MKT-77": "OUTSIDE",
  };
  const NOTES_RU: Readonly<Record<string, string>> = {
    CONTRADICTORY: "В описании товара одна цена, в поле цены — другая",
    INJECTION: "В описании товара — инструкция агенту",
    DUAL_PRICE: "Опознанному агенту показывает цену ниже, чем человеку (A5 п. 1.2)",
    REJECTS_UNIDENTIFIED: "Без подписи агента каталог не отдаёт",
    INCOMPLETE: "Карточки неполные: нет цены, наличия, условий доставки и возврата (A5 п. 1.1)",
    OUTSIDE: "Нет знака готовности — витрина вне контура (A5 п. 5)",
  };
  const mark = (key: string, label: string, note: string) =>
    `<p class="mark" data-training="${key}"><strong>${label}</strong>: <span data-training-note>${note}</span></p>`;

  it("список: пометка ровно у SHOP-3301, 3302, 3303, 4401, 5501 и MKT-77, строка своего ключа; у прочих — нет", async () => {
    const r = await get(setup(), "/shops");
    for (const s of SHOPS) {
      const c = card(r.body, "data-shop", s.id);
      const key = MARKED[s.id];
      if (key) expect(c, s.id).toContain(mark(key, "учебная — нарочно не так", NOTES_RU[key]!));
      else expect(c, s.id).not.toContain("data-training");
    }
    // Ровно шесть пометок: SHOP-1042, SHOP-2210 (REJECTS_FULFILMENT), SHOP-5003 (OUT_OF_CATEGORY) — без пометки.
    expect([...r.body.matchAll(/data-training="/g)].length).toBe(6);
    expect(Object.keys(MARKED).sort()).toEqual(SORTED.filter((id) => !["SHOP-1042", "SHOP-2210", "SHOP-5003"].includes(id)));
  });

  it("каталог: пометка в шапке у учебной витрины; у SHOP-1042 — нет; en — английская строка", async () => {
    const mm = setup();
    for (const [id, key] of Object.entries(MARKED)) {
      const r = await get(mm, `/shops/${id}`);
      expect(r.body, id).toContain(mark(key, "учебная — нарочно не так", NOTES_RU[key]!));
      expect([...r.body.matchAll(/data-training="/g)].length, id).toBe(1);
    }
    expect((await get(mm, "/shops/SHOP-1042")).body).not.toContain("data-training");
    const en = await get(mm, "/shops/SHOP-3303?lang=en");
    expect(en.body).toContain(mark("DUAL_PRICE", "training — wrong on purpose", "Shows an identified agent a lower price than a person (A5 p. 1.2)"));
    const out = await get(mm, "/shops?lang=en");
    expect(card(out.body, "data-shop", "MKT-77")).toContain(mark("OUTSIDE", "training — wrong on purpose", "No readiness mark — the shop is outside the contour (A5 p. 5)"));
  });

  it("свой набор: NORMAL без знака — «вне контура»; поведение из перечня без знака — строка поведения (одна); REJECTS_FULFILMENT со знаком — без пометки", async () => {
    const base = SHOPS.find((s) => s.id === "SHOP-1042")!;
    const own: Shop[] = [
      { ...base, id: "OWN-1", merchant_id: "MER-OWN-1", readiness_mark: false, behaviour: "NORMAL" },
      { ...base, id: "OWN-2", merchant_id: "MER-OWN-2", readiness_mark: false, behaviour: "INJECTION" },
      { ...base, id: "OWN-3", merchant_id: "MER-OWN-3", readiness_mark: true, behaviour: "REJECTS_FULFILMENT" },
    ];
    const r = await get(setup({ shops: own }), "/shops");
    expect(card(r.body, "data-shop", "OWN-1")).toContain('data-training="OUTSIDE"');
    const two = card(r.body, "data-shop", "OWN-2");
    expect(two).toContain('data-training="INJECTION"');
    expect([...two.matchAll(/data-training="/g)].length).toBe(1);
    expect(card(r.body, "data-shop", "OWN-3")).not.toContain("data-training");
  });
});

describe("З12: безопасность и граница с JSON", () => {
  const EVIL: Shop = {
    ...SHOPS[0]!,
    id: "SHOP-EVIL",
    merchant_id: "MER-EVIL",
    name: `<script>alert(1)</script>"'&`,
    category: "<b>хлеб</b>",
    items: [{ sku: "EVL-1", title: `<img src=x onerror="alert(2)">`, price: 100, currency: "RUB", in_stock: false }],
  };

  it("данные витрины экранируются в списке и каталоге", async () => {
    const mm = setup({ shops: [...SHOPS, EVIL] });
    for (const url of ["/shops", "/shops/SHOP-EVIL"]) {
      const r = await get(mm, url);
      expect(r.statusCode, url).toBe(200);
      expect(r.body, url).not.toContain("<script>");
      expect(r.body, url).not.toContain("<b>хлеб</b>");
      expect(r.body, url).toContain("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;");
      expect(r.body, url).toContain("&lt;b&gt;хлеб&lt;/b&gt;");
    }
    const c = await get(mm, "/shops/SHOP-EVIL");
    expect(c.body).not.toContain("<img");
    expect(card(c.body, "data-item", "EVL-1")).toContain("<h2>&lt;img src=x onerror=&quot;alert(2)&quot;&gt;</h2>");
    expect(card(c.body, "data-item", "EVL-1")).toContain("<dd data-stock>нет в наличии</dd>");
  });

  it("заголовки безопасности; внешних ресурсов нет; скриптов нет", async () => {
    const mm = setup();
    for (const url of ["/shops", "/shops/SHOP-1042", "/shops/SHOP-0000"]) {
      const r = await get(mm, url);
      expect(r.headers["content-security-policy"], url).toBe(UI_CSP);
      expect(r.headers["cache-control"], url).toBe("no-store");
      expect(r.headers["x-frame-options"], url).toBe("DENY");
      expect(r.headers["x-content-type-options"], url).toBe("nosniff");
      expect(r.body, url).not.toMatch(/<(script|img|link|iframe)\b/i);
      expect(r.body, url).not.toMatch(/(src|href)="(https?:)?\/\//i);
    }
  });

  it("JSON для агента и тестов не меняется: /v1/shops и каталог — прежний JSON", async () => {
    const mm = setup();
    const list = await get(mm, "/v1/shops");
    expect(list.headers["content-type"]).toMatch(/^application\/json/);
    expect((list.json() as { shops: { id: string }[] }).shops.map((s) => s.id)).toEqual(SORTED);
    const cat = await get(mm, "/v1/shops/SHOP-1042/catalog");
    expect(cat.headers["content-type"]).toMatch(/^application\/json/);
    expect((cat.json() as { shop: { id: string } }).shop.id).toBe("SHOP-1042");
  });

  it("лимит частоты — общий с /v1 (п. 6): сверх лимита — страница 429 с Retry-After, /v1 — тоже 429", async () => {
    const mm = setup({ merchants: { rateLimitPerMin: 2 } });
    expect((await get(mm, "/shops")).statusCode).toBe(200);
    expect((await get(mm, "/v1/shops")).statusCode).toBe(200);
    const r = await get(mm, "/shops/SHOP-1042?lang=en");
    expect(r.statusCode).toBe(429);
    expect(r.headers["content-type"]).toBe("text/html; charset=utf-8");
    expect(r.body).toContain("<p data-result>Too many requests. Please wait a little and try again.</p>");
    expect(Number(r.headers["retry-after"])).toBeGreaterThan(0);
    expect((await get(mm, "/v1/shops")).json()).toEqual({ code: "RATE_LIMITED" });
  });
});
