// Сопоставление кодов П3 и статусов мандата причинам ПИ §6 на границе ADP (РП43 п. 3; РП41 п. 5, РП42 п. 9).
// Таблицы полные по типу: новый код П3 или статус без строки здесь — ошибка сборки, а не догадка.
import type { MandateStatus } from "../consent/model.js";
import type { DecisionReason } from "../shared/codes.js";
import type { StateCode } from "../state/index.js";

/** Причина отказа ADP или «сообщение некорректно» — ответ HTTP 400, у процессинга ADP_UNAVAILABLE (РП43 п. 3, 8). */
export type AdpReason = DecisionReason | "INVALID";

export const STATE_TO_PI: Readonly<Record<StateCode, AdpReason>> = {
  LIMIT_EXCEEDED: "LIMIT_EXCEEDED",
  MANDATE_SCOPE: "MANDATE_SCOPE",
  MANDATE_NOT_FOUND: "MANDATE_NOT_FOUND",
  MANDATE_REVOKED: "MANDATE_REVOKED",
  MANDATE_EXPIRED: "MANDATE_EXPIRED",
  // Мандат ещё не действует — полномочий нет; «отозван» был бы ложным сигналом.
  PRINCIPAL_SIGNATURE_PENDING: "MANDATE_NOT_FOUND",
  STATE_UNAVAILABLE: "STATE_UNAVAILABLE",
  // Тот же op_ref с другой суммой; повтор по освобождённому удержанию — бюджет не подтверждён (инвариант 4).
  IDEMPOTENCY_CONFLICT: "STATE_UNAVAILABLE",
  RESERVATION_RELEASED: "STATE_UNAVAILABLE",
  REQUEST_INVALID: "INVALID",
  // На пути ADP не возникает (только commit); если всё же пришёл — не подтверждено.
  COMMIT_CONFLICT: "STATE_UNAVAILABLE",
};

/** Мандат не ACTIVE — причина по статусу (РП43 п. 2, 3; как STATUS_CODE П3, РП41 доп. п. 14). */
export const STATUS_TO_PI: Readonly<Record<Exclude<MandateStatus, "ACTIVE">, DecisionReason>> = {
  PENDING_SIGNATURE: "MANDATE_NOT_FOUND",
  REVOKED: "MANDATE_REVOKED",
  REJECTED: "MANDATE_REVOKED",
  EXPIRED: "MANDATE_EXPIRED",
  EXHAUSTED: "LIMIT_EXCEEDED",
};
