// Порт экрана мандатов (UI-К2 ч. 1, К1.2): чтения и действия банка для своего клиента. Банк реализует его своим сервером:
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
}
