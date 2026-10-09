// Сгенерировано scripts/gen-shared.mjs из docs/core/agent-protocol.yaml (x-pao-errors) — не править вручную (РП16).
// Протокол агентских операций (ПАО) 1.2.0, sha-256 4f42e8b62599c88a8291ef3dd797c92e00a4932067eef23271c76943e4407940

export const PAO_SPEC_VERSION = "1.2.0";
export const PAO_SPEC_SHA256 = "4f42e8b62599c88a8291ef3dd797c92e00a4932067eef23271c76943e4407940";
export const PAO_RETRY_VALUES = ["never","after_fix","same_key","new_key","after_human"] as const;
export const PAO_ERROR_CODES = ["AGENT_UNKNOWN","AGENT_SUSPENDED","AGENT_KEY_REVOKED","SIGNATURE_INVALID","MANDATE_NOT_FOUND","MANDATE_EXPIRED","MANDATE_REVOKED","MANDATE_SCOPE","PRINCIPAL_SIGNATURE_PENDING","LIMIT_EXCEEDED","STATE_UNAVAILABLE","CONFIRMATION_REQUIRED","CREDENTIAL_INVALID","CREDENTIALS_FORBIDDEN","IDEMPOTENCY_REQUIRED","IDEMPOTENCY_CONFLICT","RATE_LIMITED","UPSTREAM_UNAVAILABLE"] as const;

export type PaoRetry = (typeof PAO_RETRY_VALUES)[number];
export type PaoErrorCode = (typeof PAO_ERROR_CODES)[number];
export interface PaoErrorSpec {
  readonly code: PaoErrorCode;
  readonly http: number;
  readonly retry: PaoRetry;
  readonly description: string;
}

export const PAO_ERRORS: readonly PaoErrorSpec[] = [
  {
    "code": "AGENT_UNKNOWN",
    "http": 401,
    "retry": "never",
    "description": "Нет в реестре"
  },
  {
    "code": "AGENT_SUSPENDED",
    "http": 403,
    "retry": "never",
    "description": "Приостановлен"
  },
  {
    "code": "AGENT_KEY_REVOKED",
    "http": 401,
    "retry": "new_key",
    "description": "Ключ отозван или истёк"
  },
  {
    "code": "SIGNATURE_INVALID",
    "http": 401,
    "retry": "after_fix",
    "description": "Подпись, окно времени, повтор nonce"
  },
  {
    "code": "MANDATE_NOT_FOUND",
    "http": 404,
    "retry": "after_human",
    "description": "Мандат не найден"
  },
  {
    "code": "MANDATE_EXPIRED",
    "http": 409,
    "retry": "after_human",
    "description": "Мандат истёк"
  },
  {
    "code": "MANDATE_REVOKED",
    "http": 409,
    "retry": "never",
    "description": "Мандат отозван"
  },
  {
    "code": "MANDATE_SCOPE",
    "http": 409,
    "retry": "after_human",
    "description": "Продавец, категория или сумма вне мандата"
  },
  {
    "code": "PRINCIPAL_SIGNATURE_PENDING",
    "http": 409,
    "retry": "after_human",
    "description": "Мандат ещё не подписан"
  },
  {
    "code": "LIMIT_EXCEEDED",
    "http": 409,
    "retry": "after_human",
    "description": "Ограничение инструмента"
  },
  {
    "code": "STATE_UNAVAILABLE",
    "http": 503,
    "retry": "same_key",
    "description": "Состояние не подтверждено"
  },
  {
    "code": "CONFIRMATION_REQUIRED",
    "http": 428,
    "retry": "after_human",
    "description": "Нужно подтверждение"
  },
  {
    "code": "CREDENTIAL_INVALID",
    "http": 409,
    "retry": "after_fix",
    "description": "Реквизит использован, истёк, не для этого продавца"
  },
  {
    "code": "CREDENTIALS_FORBIDDEN",
    "http": 422,
    "retry": "never",
    "description": "В запросе есть платёжные реквизиты"
  },
  {
    "code": "IDEMPOTENCY_REQUIRED",
    "http": 400,
    "retry": "same_key",
    "description": "Нет ключа"
  },
  {
    "code": "IDEMPOTENCY_CONFLICT",
    "http": 409,
    "retry": "after_fix",
    "description": "Тот же ключ, другое тело"
  },
  {
    "code": "RATE_LIMITED",
    "http": 429,
    "retry": "same_key",
    "description": "Частота"
  },
  {
    "code": "UPSTREAM_UNAVAILABLE",
    "http": 503,
    "retry": "same_key",
    "description": "Компонент Платформы недоступен"
  }
];
