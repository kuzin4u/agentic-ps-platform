// Порт экрана мандатов (UI-К2 ч. 1, К1.2; подтверждение покупки — ч. 2, К2.1; история и уведомления — ч. 3, К3.2): чтения и действия банка для своего клиента. Банк реализует его своим сервером:
// чтения — из ПИ-8 (для настоящего банка их пока нет — STATUS «Открыто», `/decision` в UI-К2 ч. 3), действия — подписанные
// ключом банка записи ПИ-8 (`POST /participants/v1/mandates/{id}/sign`). На стенде — `src/env/issuer/screen.ts`.
// Порт всегда получает principal_ref из сессии экрана: чужой мандат — как неизвестный (undefined / NOT_FOUND).
// Сбой — исключение: экран отвечает 503 без кнопок (fail-closed, инвариант 3).

/** Позиция корзины — как в ПАО `MandateRequest.cart.items` (поля необязательны; нет — экран показывает «—»). */
export interface ScreenCartItem {
  readonly sku?: string;
  readonly qty?: number;
  /** Цена в минимальных единицах валюты мандата (правило совместимости 2). */
  readonly price?: number;
}

/** Мандат для человека — значения из записи Платформы (инвариант 5); номера карты и `funding_ref` нет (инвариант 1). */
export interface ScreenMandate {
  readonly id: string;
  readonly agent_code: string;
  readonly type: "INTENT" | "CART";
  readonly parent_id: string | null;
  /** Статус Платформы (ПАО `Mandate.status`); неизвестный экран показывает без действий. */
  readonly status: string;
  /** Предел в минимальных единицах + валюта ISO 4217. */
  readonly amount_limit: number;
  readonly currency: string;
  readonly valid_to: string;
  readonly merchant_scope: readonly string[];
  /** Предмет — человеку раскрывается в приложении банка (A7 п. 9.2), агенту — никогда. */
  readonly subject: string;
  readonly cart: { readonly merchant_id?: string; readonly items?: readonly ScreenCartItem[]; readonly total?: number } | null;
  /** `Mandate.hash` — то, над чем банк подписывает решение клиента (РП36 п. 3). */
  readonly hash: string;
}

export type MandateDecision = "SIGN" | "REJECT";

export type DecideResult =
  | { readonly kind: "DONE"; readonly status: string }
  | { readonly kind: "QUALIFIED_SIGNATURE_REQUIRED" }
  | { readonly kind: "NOT_PENDING"; readonly status?: string }
  | { readonly kind: "NOT_FOUND" };

/** Отзыв мандата: текущий статус после отзыва (`REVOKED` — отозван сейчас; иное — полномочий уже не было). */
export type RevokeResult = { readonly kind: "DONE"; readonly status: string } | { readonly kind: "NOT_FOUND" };

/**
 * Запрос подтверждения покупки (П6, РП50 п. 1) для человека — итоговые значения из записи Платформы (инвариант 5); номера
 * карты и `confirmation_ref` нет (ссылку видит только агент, РП50 п. 7). Чтения для настоящего банка — STATUS «Открыто».
 */
export interface ScreenConfirmation {
  readonly id: string;
  readonly agent_code: string;
  readonly mandate_id: string;
  readonly merchant_id: string;
  /** Сумма в минимальных единицах + валюта ISO 4217 (правило совместимости 2). */
  readonly amount: number;
  readonly currency: string;
  readonly order_ref: string;
  /** Статус П6 (`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `USED`); неизвестный экран показывает без действий. */
  readonly status: string;
  readonly expires_at: string;
  /** `totals_hash` этого итога (РП50 п. 4): форма несёт его, банк подписывает его, а не пересчитанный при нажатии. */
  readonly totals_hash: string;
}

/** Агент для человека — класс и статус из реестра (инвариант 5); коды Платформы, текст — словарь экрана. */
export interface ScreenAgent {
  readonly agent_code: string;
  /** Класс реестра (`BUYER`, `SELLER`, `SURFACE`, `SERVICE`); неизвестный экран показывает кодом. */
  readonly class: string;
  /** Статус реестра (`ACTIVE`, `SUSPENDED`, `EXCLUDED`); неизвестный экран показывает кодом. */
  readonly status: string;
}

/**
 * Запись истории мандата (UI-К2 ч. 3, К3.2) — из журнала согласий (инвариант 6: только чтение). `kind` — код записи журнала
 * (`MANDATE_REQUESTED`, `MANDATE_SIGNED` …), неизвестный экран показывает кодом; `mandate_id` — мандат записи (у CART в
 * истории есть и записи родителя INTENT). Предел — только у записи запроса, парой с валютой (правило совместимости 2).
 */
export interface ScreenHistoryEntry {
  readonly at: string;
  readonly kind: string;
  readonly mandate_id: string;
  readonly amount_limit?: number;
  readonly currency?: string;
}

/**
 * Уведомление клиента через банк (ПИ-8 `GET /participants/v1/notifications`, РП46 (б); A3 п. 5.3) — только коды и ссылки
 * (инвариант 1). `type` — `client.*`, неизвестный экран показывает кодом; `reason` — чей предел у `client.limit_declined`.
 */
export interface ScreenNotification {
  readonly at: string;
  readonly type: string;
  readonly mandate_id?: string;
  readonly agent_code?: string;
  readonly reason?: string;
}

export type ConfirmDecision = "APPROVE" | "REJECT";

/** Решение человека: записано; итог не тот, что видел человек; запрос уже не ждёт (текущий статус); неизвестный. */
export type ConfirmResult =
  | { readonly kind: "DONE"; readonly status: string }
  | { readonly kind: "TOTALS_CHANGED" }
  | { readonly kind: "NOT_PENDING"; readonly status?: string }
  | { readonly kind: "NOT_FOUND" };

export interface MandatesScreenPort {
  /** Мандаты клиента. */
  mandates(principal_ref: string): Promise<readonly ScreenMandate[]>;
  /** Мандат клиента; чужой и неизвестный — undefined. */
  mandate(principal_ref: string, id: string): Promise<ScreenMandate | undefined>;
  /**
   * Решение клиента по мандату в ожидании подписи: банк подписывает и шлёт ПИ-8. Подпись и согласие на токен — одно
   * действие (РП12): `SIGN` — с согласием, `REJECT` — без (правка по `/audit` К1.2, решение владельца 02.11).
   */
  decide(principal_ref: string, id: string, decision: MandateDecision): Promise<DecideResult>;
  /** Отзыв мандата клиентом (ПИ-8 `revoke`, РП38): авторизованное до отзыва исполняется (инвариант 8). */
  revoke(principal_ref: string, id: string): Promise<RevokeResult>;
  /**
   * Отзыв всех полномочий клиента одним действием (ПИ-8 `revoke-all`, РП45 п. 4): `revocation_ref` — от экрана, повтор после
   * сбоя — тем же; ответ — число отозванных мандатов.
   */
  revokeAll(principal_ref: string, revocation_ref: string): Promise<{ readonly revoked: number }>;
  /** Запросы подтверждения покупки клиента (любого статуса; экран сам отбирает ждущие решения). */
  confirmations(principal_ref: string): Promise<readonly ScreenConfirmation[]>;
  /** Запрос клиента; чужой, неизвестный и запрос без найденного мандата — undefined (fail-closed). */
  confirmation(principal_ref: string, id: string): Promise<ScreenConfirmation | undefined>;
  /**
   * Решение человека по запросу (ПИ-8 `POST /participants/v1/confirmations/{id}`, РП50 п. 4–5): банк подписывает запись над
   * `totals_hash` из формы — итогом, который видел человек; `instrument_chosen` банк не передаёт (РП51 п. 13).
   */
  confirm(principal_ref: string, id: string, decision: ConfirmDecision, totals_hash: string): Promise<ConfirmResult>;
  /**
   * Агент из реестра (UI-К2 ч. 2, К2.2): класс и статус; нет в реестре — undefined. Сбой — исключение: экран показывает
   * «статус агента не прочитан» и работает дальше — подсказка поясняет, отказ ставит ADP по suspended_at (решение владельца
   * 03.11). Для настоящего банка чтения статуса агента в ПИ-8 нет (маршрут — только эквайреру, РП57 п. 6) — STATUS «Открыто».
   */
  agent(agent_code: string): Promise<ScreenAgent | undefined>;
  /**
   * История мандата клиента (UI-К2 ч. 3, К3.2): записи журнала по порядку; чужой и неизвестный — undefined. Сбой и
   * нарушенная цепочка журнала — исключение: экран отвечает 503 (инвариант 3). Для настоящего банка чтения истории мандата
   * в ПИ-8 нет — `/decision` UI-К2 ч. 3 (К3.1), STATUS «Открыто»; на стенде — выписка журнала в памяти.
   */
  history(principal_ref: string, id: string): Promise<readonly ScreenHistoryEntry[] | undefined>;
  /**
   * Уведомления клиента по порядку ленты (UI-К2 ч. 3, К3.2): банк читает свою ленту ПИ-8 `GET /participants/v1/notifications`
   * и отбирает записи клиента по `principal_ref`. Сбой — исключение (503).
   */
  notifications(principal_ref: string): Promise<readonly ScreenNotification[]>;
}
