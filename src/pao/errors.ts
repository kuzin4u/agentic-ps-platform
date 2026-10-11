// Тело ошибки ПАО §6 строго по схеме Error: code, message, norm, retry (РП23 п. 7).
// HTTP и retry — только из x-pao-errors (src/shared/pao-errors.generated.ts, РП16); поля RFC 9457 — решением в PS-05.
import { PAO_ERRORS, type PaoErrorCode, type PaoRetry } from "../shared/pao-errors.generated.js";

export interface PaoErrorBody {
  readonly code: PaoErrorCode;
  readonly message: string;
  readonly norm?: string;
  readonly retry: PaoRetry;
}

export interface PaoErrorReply {
  readonly http: number;
  readonly body: PaoErrorBody;
}

const BY_CODE = new Map(PAO_ERRORS.map((e) => [e.code, e]));

/** Ответ с ошибкой ПАО; сообщение по умолчанию — причина из таблицы. Код вне таблицы — исключение (инвариант 3). */
export function paoError(code: PaoErrorCode, norm?: string, message?: string): PaoErrorReply {
  const spec = BY_CODE.get(code);
  if (!spec) throw new Error(`Код ошибки вне x-pao-errors: ${String(code)}`);
  const body: PaoErrorBody = {
    code,
    message: message ?? spec.description,
    ...(norm !== undefined ? { norm } : {}),
    retry: spec.retry,
  };
  return { http: spec.http, body };
}
