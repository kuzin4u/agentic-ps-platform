// Журнал согласий (П2, PS-06) хэширует записи через canonicalJson ядра. До v0.5.0 Date, Map и экземпляры классов
// молча становились {} — хэш-цепочка расходилась бы между записью и проверкой (расхождение № 18 ядра, К12).
// Тест закрепляет поведение ядра, на которое опирается журнал: такое значение — отказ, а не догадка.
import { canonicalJson } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";

class Subject {
  readonly amount = 1000;
}

describe("canonicalJson ядра для журнала согласий (К12 ядра v0.5.0)", () => {
  it.each([
    ["Date", { valid_to: new Date("2026-10-17T10:00:00Z") }],
    ["Map", { cart: new Map([["sku", 1]]) }],
    ["Set", { skus: new Set(["a"]) }],
    ["экземпляр класса", { subject: new Subject() }],
    ["Buffer", { blob: Buffer.from("x") }],
  ])("%s — TypeError NON_PLAIN_OBJECT", (_name, payload) => {
    expect(() => canonicalJson(payload)).toThrow(TypeError);
    expect(() => canonicalJson(payload)).toThrow("NON_PLAIN_OBJECT");
  });

  it.each([
    ["undefined в массиве", { items: [undefined] }],
    ["bigint", { amount: 1n }],
    ["функция", { f: () => 1 }],
  ])("%s — TypeError NON_JSON_VALUE", (_name, payload) => {
    expect(() => canonicalJson(payload)).toThrow("NON_JSON_VALUE");
  });

  it("NaN — TypeError NON_FINITE_NUMBER", () => {
    expect(() => canonicalJson({ amount: Number.NaN })).toThrow("NON_FINITE_NUMBER");
  });

  it("дата строкой ISO 8601 и простой объект — порядок ключей канонический, хэш не зависит от порядка полей", () => {
    const a = canonicalJson({ valid_to: "2026-10-17T10:00:00.000Z", amount_limit: 1000, currency: "RUB" });
    const b = canonicalJson({ currency: "RUB", amount_limit: 1000, valid_to: "2026-10-17T10:00:00.000Z" });
    expect(a).toBe(b);
    expect(a).toBe('{"amount_limit":1000,"currency":"RUB","valid_to":"2026-10-17T10:00:00.000Z"}');
  });

  it("поле со значением undefined пропускается, как прежде", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});
