// Коды отказа витрин эмулятора продавцов и их HTTP-статусы (PS-12; Р26 п. 5 агента). Один источник для эмулятора
// и для `agentic-ps-platform/fixtures`: агент сверяет свой мок с этим перечнем, а не с литералами в тестах.
// Ошибки витрин — `{code}` эмулятора, не ПАО §6 (расхождение № 17). Модуль без зависимостей — фикстуры его импортируют.
import type { MerchantAuthError } from "./verify.js";

export type MerchantErrorCode =
  | "AGENT_UNIDENTIFIED"
  | MerchantAuthError
  | "SHOP_NOT_FOUND"
  | "ORDER_NOT_FOUND"
  | "ORDERS_NOT_ACCEPTED"
  | "ITEM_INVALID"
  | "ITEM_INCOMPLETE"
  | "PACKAGE_INVALID"
  | "PACKAGE_MISMATCH"
  | "ORDER_NOT_PAYABLE"
  | "UPSTREAM_UNAVAILABLE"
  | "RATE_LIMITED";

export const MERCHANT_ERROR_HTTP: Readonly<Record<MerchantErrorCode, number>> = Object.freeze({
  AGENT_UNIDENTIFIED: 403,
  KEY_UNKNOWN: 401,
  AGENT_MISMATCH: 401,
  KEY_EXPIRED: 401,
  SIGNATURE_INVALID: 401,
  SHOP_NOT_FOUND: 404,
  ORDER_NOT_FOUND: 404,
  ORDERS_NOT_ACCEPTED: 409,
  ITEM_INVALID: 422,
  ITEM_INCOMPLETE: 422,
  PACKAGE_INVALID: 422,
  PACKAGE_MISMATCH: 409,
  ORDER_NOT_PAYABLE: 409,
  UPSTREAM_UNAVAILABLE: 503,
  RATE_LIMITED: 429,
});
