// Фикстуры витрин и агентов для тестов агента (AG-04 лёгкий мок, AG-09 поиск и зоны) — из тех же данных,
// что эмулятор продавцов (src/env/merchants/shops.ts): один источник. Тестовый интерфейс, не контракт (инвариант 10).
// Закрытых ключей нет: пару генерирует потребитель, Платформа получает только открытый ключ (РП23 п. 2).
import { MERCHANT_ERROR_HTTP, type MerchantErrorCode } from "../env/merchants/errors.js";
import { SHOPS, byShopId, catalogView, zoneOf, type ShopBehaviour, type ShopItem, type Zone } from "../env/merchants/shops.js";

export type { MerchantErrorCode, ShopBehaviour, ShopItem, Zone };

/**
 * Коды отказа витрин эмулятора с HTTP-статусами (Р26 п. 5 агента; AG-04, AG-09): тело отказа витрины — `{code}`.
 * Перечень закрыт: другой код от витрины — расхождение эмулятора, а не новый код.
 */
export const MERCHANT_ERROR_CODES: readonly { readonly code: MerchantErrorCode; readonly http: number }[] = Object.freeze(
  (Object.entries(MERCHANT_ERROR_HTTP) as [MerchantErrorCode, number][])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([code, http]) => Object.freeze({ code, http })),
);

export interface MerchantFixture {
  readonly id: string;
  readonly merchant_id: string;
  readonly name: string;
  readonly mcc: string;
  readonly category: string;
  readonly zone: Zone;
  readonly readiness_mark: boolean;
  readonly behaviour: ShopBehaviour;
  /** Каталог, как его видит человек (запрос без подписи). */
  readonly items: readonly Omit<ShopItem, "agent_price">[];
  /** Каталог, как его видит опознанный агент: у DUAL_PRICE цена ниже (A5 п. 1.2). */
  readonly agent_items: readonly Omit<ShopItem, "agent_price">[];
}

export const MERCHANT_FIXTURES: readonly MerchantFixture[] = Object.freeze(
  [...SHOPS]
    .sort(byShopId)
    .map((s) =>
      Object.freeze({
        id: s.id,
        merchant_id: s.merchant_id,
        name: s.name,
        mcc: s.mcc,
        category: s.category,
        zone: zoneOf(s),
        readiness_mark: s.readiness_mark,
        behaviour: s.behaviour,
        items: Object.freeze(s.items.map((i) => Object.freeze(catalogView(i, false)))),
        agent_items: Object.freeze(s.items.map((i) => Object.freeze(catalogView(i, true)))),
      }),
    ),
);

export interface AgentFixture {
  readonly agent_code: string;
  readonly class: "BUYER" | "SELLER" | "SURFACE" | "SERVICE";
  readonly model: string;
  readonly runtime: string;
  /** Оператор агента — для допуска в стенде (только стенд, расхождение №9). */
  readonly operator: string;
  /** false — агент заведомо не в реестре (отказ витрины и шлюза: AGENT_UNKNOWN, KEY_UNKNOWN). */
  readonly registered: boolean;
}

export const AGENT_FIXTURES: readonly AgentFixture[] = Object.freeze([
  Object.freeze({ agent_code: "nspk:agent:buyref-01:v1", class: "BUYER", model: "buyer-agent-ref", runtime: "node-20", operator: "op-buyref", registered: true }),
  Object.freeze({ agent_code: "nspk:agent:buyref-02:v1", class: "BUYER", model: "buyer-agent-ref", runtime: "node-20", operator: "op-buyref", registered: true }),
  Object.freeze({ agent_code: "nspk:agent:stranger-01:v1", class: "BUYER", model: "unknown-agent", runtime: "unknown", operator: "op-stranger", registered: false }),
] satisfies AgentFixture[]);

/** Заявление о допуске по фикстуре: ключ — открытый ключ потребителя (DER SPKI, каноническая base64). */
export const agentApplication = (
  f: AgentFixture,
  key: { readonly alg: string; readonly public_key: string },
): Record<string, unknown> => ({
  agent_code: f.agent_code,
  class: f.class,
  model: f.model,
  runtime: f.runtime,
  alg: key.alg,
  public_key: key.public_key,
});
