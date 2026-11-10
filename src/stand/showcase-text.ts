// Тексты страницы витрин стенда (РП58 дополнение З12; ru / en, правило совместимости 3). Данные витрины (названия, категории,
// товары) — слова продавца, не переводятся и выводятся через esc.
//
// Строки пометки учебных витрин (п. 4, В1 (а), В2 (а)) — только из описания фикстуры, у каждой источник:
//   CONTRADICTORY        — src/env/merchants/shops.ts, SHOP-3301: имя «Пекарня с противоречивой карточкой», описание
//                          «Цена: 290 ₽ за буханку.» при price: 32000;
//   INJECTION            — shops.ts, SHOP-3302: имя «Пекарня с инструкцией в описании» и текст описания;
//   DUAL_PRICE           — shops.ts, JSDoc ShopItem.agent_price: «Цена, которую витрина DUAL_PRICE показывает опознанному
//                          агенту (A5 п. 1.2 — нарушение)»;
//   REJECTS_UNIDENTIFIED — src/env/merchants/server.ts, каталог: «неопознанным SHOP-4401 отказывает»;
//   INCOMPLETE           — shops.ts, комментарии SHOP-5501: без returns, без delivery_options, без цены и валюты, без наличия;
//   OUTSIDE              — shops.ts, JSDoc Zone: «CONTOUR — со знаком готовности (РП22 п. 7, A5 п. 5), иначе OUTSIDE».
export const SHOWCASE_TEXT = {
  ru: {
    title: "Витрины продавцов",
    lead: "Эмулятор продавцов стенда — вид для человека. Агент и тесты читают JSON по адресам /v1/shops.",
    shopId: "id",
    sells: "Что продаёт",
    items: "Товаров",
    zone: "Контур",
    zones: { CONTOUR: "в контуре", OUTSIDE: "вне контура" },
    back: "К списку витрин",
    empty: "Товаров нет",
    price: "Цена",
    priceMissing: "цена не указана",
    stock: "Наличие",
    inStock: "в наличии",
    outOfStock: "нет в наличии",
    stockUnknown: "наличие не указано",
    notFound: "Витрина не найдена",
    tooMany: "Слишком много обращений. Подождите немного и повторите.",
    unavailable: "Страница временно недоступна, попробуйте позже",
    training: "учебная — нарочно не так",
    trainingNotes: {
      CONTRADICTORY: "В описании товара одна цена, в поле цены — другая",
      INJECTION: "В описании товара — инструкция агенту",
      DUAL_PRICE: "Опознанному агенту показывает цену ниже, чем человеку (A5 п. 1.2)",
      REJECTS_UNIDENTIFIED: "Без подписи агента каталог не отдаёт",
      INCOMPLETE: "Карточки неполные: нет цены, наличия, условий доставки и возврата (A5 п. 1.1)",
      OUTSIDE: "Нет знака готовности — витрина вне контура (A5 п. 5)",
    },
  },
  en: {
    title: "Merchant shops",
    lead: "Stand merchant emulator — a view for people. The agent and tests read JSON at /v1/shops.",
    shopId: "id",
    sells: "Sells",
    items: "Items",
    zone: "Contour",
    zones: { CONTOUR: "in the contour", OUTSIDE: "outside the contour" },
    back: "Back to shops",
    empty: "No items",
    price: "Price",
    priceMissing: "price not given",
    stock: "Availability",
    inStock: "in stock",
    outOfStock: "out of stock",
    stockUnknown: "availability not given",
    notFound: "Shop not found",
    tooMany: "Too many requests. Please wait a little and try again.",
    unavailable: "The page is temporarily unavailable, please try later",
    training: "training — wrong on purpose",
    trainingNotes: {
      CONTRADICTORY: "The item description gives one price, the price field another",
      INJECTION: "The item description contains an instruction to the agent",
      DUAL_PRICE: "Shows an identified agent a lower price than a person (A5 p. 1.2)",
      REJECTS_UNIDENTIFIED: "Does not give the catalogue without an agent signature",
      INCOMPLETE: "Incomplete cards: no price, availability, delivery or return terms (A5 p. 1.1)",
      OUTSIDE: "No readiness mark — the shop is outside the contour (A5 p. 5)",
    },
  },
} as const;
