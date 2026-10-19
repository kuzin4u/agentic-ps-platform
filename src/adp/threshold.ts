// П4 Порог подтверждения (SPEC §6 п. 10, РП44 п. 5): меньшее из рыночного confirm_above_kop и клиентского
// Limits.confirm_above (A3 п. 7.2) — из записи лимитов клиента (РП45 п. 2). Порог — пара «сумма + валюта» (правило
// совместимости 2); рыночный — в рублях.
import { isCurrencyCode } from "@kuzin4u/agentic-core";
import type { ClientLimits, ClientRef } from "../participants/limits.js";

export interface Threshold {
  readonly amount: number;
  readonly currency: string;
}

/** Валюта рыночного порога: confirm_above_kop — копейки RUB (PARAMS, РП44 п. 5). */
export const MARKET_THRESHOLD_CURRENCY = "RUB";

/**
 * Лимиты клиента мандата (ПИ-8 Limits, РП45 п. 1–2): действующая запись банка — одно чтение на решение; из неё же
 * клиентский порог (ClientThresholds РП44 п. 5), per_operation, merchant_categories и per_period. Записи нет —
 * undefined; сбой — исключение (→ STATE_UNAVAILABLE). Запись проверяет ADP: не по форме — тоже не подтверждено.
 */
export interface ClientLimitsSource {
  get(client: ClientRef): Promise<unknown>;
}

/** Клиентский порог из записи лимитов: confirm_above парой с currency записи; не задан — undefined (рыночный). */
export const clientThreshold = (l: ClientLimits): unknown =>
  l.confirm_above === undefined ? undefined : { amount: l.confirm_above, currency: l.currency };

/** Ответ порта по форме: целое ≥ 0 и валюта ISO 4217; иначе undefined (не подтверждено, не догадка). */
export function parseClientThreshold(v: unknown): Threshold | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const { amount, currency } = v as Record<string, unknown>;
  if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount < 0) return undefined;
  if (!isCurrencyCode(currency)) return undefined;
  return { amount, currency };
}

/**
 * Действующий порог для операции в валюте currency: меньшее из рыночного и клиентского. Порог в другой валюте —
 * не определён (копейки и центы несравнимы, инвариант 3): undefined → STATE_UNAVAILABLE.
 */
export function effectiveThreshold(market: Threshold, client: Threshold | undefined, currency: string): number | undefined {
  if (market.currency !== currency) return undefined;
  if (client === undefined) return market.amount;
  if (client.currency !== currency) return undefined;
  return Math.min(market.amount, client.amount);
}
