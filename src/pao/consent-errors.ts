// П9 Отказы журнала согласий → коды ПАО (РП33 п. 1–2): новых кодов нет, причина в поле агенту не раскрывается.
import { ConsentIntegrityError, ConsentKeyReused, ConsentStateUnknown } from "../consent/model.js";
import { ConsentRequestRejected } from "../consent/terms.js";
import { paoError, type PaoErrorReply } from "./errors.js";

/** Сообщение при отклонённом клиентом родителе: в схеме Error нет поля причины (РП33 п. 2). */
export const PARENT_REJECTED_MESSAGE = "Родитель отклонён клиентом (REJECTED)";

/** Код ПАО для исключения журнала; undefined — не отказ журнала (сбой: UPSTREAM_UNAVAILABLE у вызывающего). */
export function consentErrorReply(err: unknown): PaoErrorReply | undefined {
  if (err instanceof ConsentIntegrityError || err instanceof ConsentStateUnknown) {
    return paoError("STATE_UNAVAILABLE", "A7 п. 4");
  }
  // Тот же ключ — другой запрос, в любой срок (РП33 доп.).
  if (err instanceof ConsentKeyReused) return paoError("IDEMPOTENCY_CONFLICT");
  if (!(err instanceof ConsentRequestRejected)) return undefined;
  switch (err.reason) {
    case "FIELD_INVALID":
      return paoError("REQUEST_INVALID", "A7 п. 2");
    case "PARENT_NOT_FOUND":
      return paoError("MANDATE_NOT_FOUND", "A7 п. 1");
    case "PARENT_NOT_ACTIVE":
      switch (err.parentStatus) {
        case "PENDING_SIGNATURE":
          return paoError("PRINCIPAL_SIGNATURE_PENDING", "A7 п. 3");
        case "EXPIRED":
          return paoError("MANDATE_EXPIRED", "A7 п. 2");
        case "REJECTED":
          return paoError("MANDATE_REVOKED", "A7 п. 3", PARENT_REJECTED_MESSAGE);
        case "REVOKED":
          return paoError("MANDATE_REVOKED", "A7 п. 6");
        // Бюджет родителя закреплён целиком — состояние подтверждено и конечно, не 503 с повтором (РП41 доп. п. 20).
        case "EXHAUSTED":
          return paoError("LIMIT_EXCEEDED", "A3 п. 4");
        // Иной статус родителя — не догадка (инвариант 3).
        default:
          return paoError("STATE_UNAVAILABLE", "A7 п. 4");
      }
    case "PARENT_MISMATCH":
      // Родитель — CART: ошибка формы запроса; другой принципал или валюта — вне пределов родителя.
      return err.field === "parent_id" ? paoError("REQUEST_INVALID", "A7 п. 1") : paoError("MANDATE_SCOPE", "A7 п. 5");
    case "SCOPE_WIDENED":
      return paoError("MANDATE_SCOPE", "A7 п. 5");
    default: {
      // Новое основание отказа — ошибка сборки, а не молчаливый 503.
      const unknown: never = err.reason;
      throw new Error(`ПАО: основание отказа журнала без кода ПАО: ${String(unknown)}`);
    }
  }
}
