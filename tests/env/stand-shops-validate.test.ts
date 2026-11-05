// РП25 дополнение #106 п. 4: сверка набора витрин при createStand — закрытый перечень правил (а)–(е), fail-closed.
// По одному отрицательному тесту на правило; набор по умолчанию (SHOPS) проходит ту же сверку; неверный набор — стенд
// не создаётся. Номер карты собирается во время теста — литерала в репозитории нет (инвариант 1, guard.py).
import { isGtin } from "@kuzin4u/agentic-core/catalog";
import { describe, expect, it } from "vitest";
import { validateShopSet } from "../../src/env/merchants/shops.js";
import { SHOPS, type Shop } from "../../src/fixtures/index.js";
import { createStand } from "../../src/stand/index.js";

function luhnOk(s: string): boolean {
  let sum = 0;
  for (let i = 0; i < s.length; i++) {
    let x = Number(s[s.length - 1 - i]);
    if (i % 2 === 1) x = x * 2 > 9 ? x * 2 - 9 : x * 2;
    sum += x;
  }
  return sum % 10 === 0;
}
function withLuhn(body: string): string {
  for (let d = 0; d <= 9; d++) if (luhnOk(body + d)) return body + d;
  throw new Error("нет контрольной цифры");
}
const PAN = withLuhn("2200" + "0".repeat(11));

/** EAN-13 с верной контрольной цифрой GTIN, который к тому же проходит сумму Луна, — риск правила (е). */
function gtinPassingLuhn(): string {
  for (let n = 0; n < 10_000; n++) {
    for (let d = 0; d <= 9; d++) {
      const s = `46000000${String(n).padStart(4, "0")}${d}`;
      if (isGtin(s) && luhnOk(s)) return s;
    }
  }
  throw new Error("не найден");
}

const base = (): Shop => ({
  id: "SHOP-9001",
  merchant_id: "MER-9001",
  name: "Пекарня 9001",
  inn: "0000900107",
  mcc: "5462",
  category: "bakery",
  payment_methods: ["card", "sbp"],
  delivery_regions: ["RU-MOW"],
  returns: { days: 0, text: "возврату не подлежит" },
  readiness_mark: true,
  behaviour: "NORMAL",
  items: [
    {
      sku: "BRD-01",
      title: "Хлеб",
      price: 45_000,
      currency: "RUB",
      delivery_options: [{ method: "PICKUP", min_days: 0, max_days: 0, cost: 0, currency: "RUB" }],
      gtin: null,
    },
  ],
});
/** Витрина с изменением поверх основы; `item` — изменение первого товара. */
const shop = (over: Record<string, unknown> = {}, item: Record<string, unknown> = {}): Shop => {
  const b = base();
  return { ...b, ...over, items: [{ ...b.items[0]!, ...item }] } as Shop;
};
const check = (set: unknown) => () => validateShopSet(set);

describe("#106 п. 4: сверка набора витрин стенда (а)–(е)", () => {
  it("набор по умолчанию SHOPS и своя полная витрина проходят сверку", () => {
    expect(check(SHOPS)).not.toThrow();
    expect(check([shop()])).not.toThrow();
    expect(check([...SHOPS, shop()])).not.toThrow();
  });

  it("(а) пустой набор, id вне формы, повтор id и merchant_id", () => {
    expect(check([])).toThrow("createStand: набор витрин — правило (а) непустой массив");
    expect(check([shop({ id: "SHOP/../x" })])).toThrow("createStand: витрина ? — правило (а) id");
    expect(check([shop(), shop({ merchant_id: "MER-9002" })])).toThrow("createStand: витрина SHOP-9001 — правило (а) id не уникален");
    expect(check([shop(), shop({ id: "SHOP-9002" })])).toThrow("createStand: витрина SHOP-9002 — правило (а) merchant_id не уникален");
  });

  it("(б) behaviour вне SHOP_BEHAVIOURS, readiness_mark не boolean", () => {
    expect(check([shop({ behaviour: "FRIENDLY" })])).toThrow("createStand: витрина SHOP-9001 — правило (б) behaviour");
    expect(check([shop({ readiness_mark: "yes" })])).toThrow("createStand: витрина SHOP-9001 — правило (б) readiness_mark");
  });

  it("(в) ИНН с неверной контрольной цифрой, MCC не из 4 цифр", () => {
    expect(check([shop({ inn: "0000900108" })])).toThrow("createStand: витрина SHOP-9001 — правило (в) inn");
    expect(check([shop({ mcc: "546" })])).toThrow("createStand: витрина SHOP-9001 — правило (в) mcc");
  });

  it("(г) payment_methods не строки, регион не ISO 3166-2, returns без текста; [] способов допустим", () => {
    expect(check([shop({ payment_methods: [] })])).not.toThrow();
    expect(check([shop({ payment_methods: [1] })])).toThrow("createStand: витрина SHOP-9001 — правило (г) payment_methods");
    expect(check([shop({ delivery_regions: ["Москва"] })])).toThrow("createStand: витрина SHOP-9001 — правило (г) delivery_regions");
    expect(check([shop({ returns: { days: 14, text: "" } })])).toThrow("createStand: витрина SHOP-9001 — правило (г) returns");
  });

  it("(д) цена дробная, цена без валюты, повтор sku, стоимость доставки отрицательная; INCOMPLETE без цены допустим", () => {
    expect(check([shop({}, { price: 450.5 })])).toThrow("createStand: витрина SHOP-9001 — правило (д) price");
    expect(check([shop({}, { currency: undefined })])).toThrow("createStand: витрина SHOP-9001 — правило (д) price без currency");
    const b = base();
    expect(check([{ ...b, items: [b.items[0]!, b.items[0]!] }])).toThrow("createStand: витрина SHOP-9001 — правило (д) sku не уникален");
    expect(check([shop({}, { delivery_options: [{ method: "PICKUP", min_days: 0, max_days: 0, cost: -1, currency: "RUB" }] })])).toThrow(
      "createStand: витрина SHOP-9001 — правило (д) delivery_options.cost",
    );
    expect(check([shop({ behaviour: "INCOMPLETE" }, { price: undefined, currency: undefined })])).not.toThrow();
  });

  it("(е) серия номера карты в тексте витрины — отказ; gtin — по isGtin ядра, EAN-13 с суммой Луна проходит", () => {
    expect(check([shop({}, { description: `оплата картой ${PAN}` })])).toThrow("createStand: витрина SHOP-9001 — правило (е) реквизиты карты");
    expect(check([shop({}, { cvv: "000" })])).toThrow("createStand: витрина SHOP-9001 — правило (е) реквизиты карты");
    const gtin = gtinPassingLuhn();
    expect(luhnOk(gtin)).toBe(true);
    expect(check([shop({}, { gtin })])).not.toThrow();
    expect(check([shop({}, { gtin: "4600000000001" + "0" })])).toThrow("createStand: витрина SHOP-9001 — правило (е) gtin");
  });

  it("createStand с неверным набором — исключение, стенд не создаётся", () => {
    expect(() => createStand({ shops: [shop({ inn: "0000900108" })] })).toThrow("createStand: витрина SHOP-9001 — правило (в) inn");
    expect(() => createStand({ shops: [] })).toThrow("правило (а)");
  });
});
