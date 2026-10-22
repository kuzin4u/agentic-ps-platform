// Сгенерировано scripts/gen-shared.mjs из docs/core/processing-interface.yaml — не править вручную.
// Интерфейсы Платформы с процессингом и участниками 1.0.0-draft, sha-256 2236c72a3b7fc9ee33267de2179c0114eb7a3874f201c3d1053341922e2a8631
// Номера полей и кодов внешних форматов здесь нет: только каноническая модель [альбом] (РП6).

export const PI_VERSION = "1.0.0-draft";
export const PI_SPEC_SHA256 = "2236c72a3b7fc9ee33267de2179c0114eb7a3874f201c3d1053341922e2a8631";

export interface Instrument {
  kind: "AGENT_TOKEN" | "ACCOUNT_LINK" | "CARD_TOKEN";
  token_ref?: string;
  cryptogram?: string;
  account_link_ref?: string;
  issuer_id?: string;
}

export interface Merchant {
  id?: string;
  mcc?: string;
  acquirer_id?: string;
  name?: string;
}

/** Признак агентской операции (ПИ-2). Неагентская операция (ADP — BYPASS, мимо проверок): instrument.kind = CARD_TOKEN и признака нет — aoi нет, aoi: null или indicator: false без agent_code и mandate_id (нет или null); эквайрер может передавать поле признака во всех сообщениях (РП49 (в)). indicator: false с agent_code или mandate_id у CARD_TOKEN — противоречивый признак, агентская: DECLINE / CREDENTIAL_INVALID. Агентский инструмент (AGENT_TOKEN, ACCOUNT_LINK) — агентская при любом aoi; aoi без indicator — AOI_MISSING. */
export interface Aoi {
  indicator?: boolean;
  agent_code?: string;
  mandate_id?: string;
  fulfilment_ref?: string | null;
  deal_ref?: string | null;
}

export interface CanonicalMessage {
  op_ref: string;
  msg_type: "AUTH_REQUEST" | "ISSUER_RESPONSE" | "REVERSAL" | "PRESENTMENT" | "REFUND" | "CHARGEBACK" | "AUTH_EXPIRED";
  seq?: number;
  channel: "CARD" | "SBP";
  amount: number;
  currency: string;
  merchant: Merchant;
  instrument: Instrument;
  aoi?: Aoi;
  confirmation_ref?: string | null;
  order_ref?: string;
  reservation_id?: string | null;
  issuer_approved?: boolean | null;
  ts?: string;
}

/** Пары в ответе ADP (РП19): APPROVE, BYPASS — reason null; DECLINE — код ПИ §6, кроме CONFIRMATION_REQUIRED и ADP_UNAVAILABLE; CONFIRMATION_REQUIRED — reason CONFIRMATION_REQUIRED. ADP_UNAVAILABLE — только в решении процессинга при таймауте ADP (DECLINE / ADP_UNAVAILABLE). Несогласованная пара — отказ. */
export interface Decision {
  decision: "APPROVE" | "DECLINE" | "CONFIRMATION_REQUIRED" | "BYPASS";
  reason?: null | "AOI_MISSING" | "AOI_MISMATCH" | "AGENT_UNKNOWN" | "AGENT_SUSPENDED" | "CREDENTIAL_INVALID" | "MANDATE_NOT_FOUND" | "MANDATE_EXPIRED" | "MANDATE_REVOKED" | "MANDATE_SCOPE" | "LIMIT_EXCEEDED" | "STATE_UNAVAILABLE" | "CONFIRMATION_REQUIRED" | "ADP_UNAVAILABLE";
  /** Дробление по мандату в окне (РП44 п. 7): true — только у CONFIRMATION_REQUIRED по доле (операция не выше порога, но с одобрениями и записями «в работе» в окне split_window_sec по корневому INTENT их не меньше split_min_ops и сумма выше порога); false — у CONFIRMATION_REQUIRED по порогу одной операции; у прочих решений поля нет. */
  split_detected?: boolean;
  reservation_id?: string | null;
  agent_level?: number;
  mandate_left_after?: number;
  decided_in_ms: number;
}

/** Лимиты клиента (РП45 п. 1, 3). Суммы — целые ≥ 0 в минимальных единицах, парой с currency (ISO 4217, обязательна при любом поле суммы); per_period и period — только вместе; period — календарный период в часовом поясе client_limit_period_tz. Неизвестное поле или period — 422 LIMITS_UNSUPPORTED. per_operation — сумма > per_operation → LIMIT_EXCEEDED; per_period — второй счёт удержаний ядра, резерв тем же op_key после мандата; merchant_categories — MCC вне списка → MANDATE_SCOPE; confirm_above — клиентский порог подтверждения (меньшее с рыночным, РП44 п. 5). */
export interface Limits {
  per_operation?: number;
  per_period?: number;
  period?: "DAY" | "MONTH";
  merchant_categories?: Array<string>;
  confirm_above?: number;
  currency?: string;
}

/** Подписанная банком запись лимитов (РП45 п. 1). Подпись Ed25519 ключом банка над canonicalJson записи {context, participant_code, kid, principal_ref, version, limits, issued_at}; context = pao:participant-limits:v1, principal_ref — из пути. Только вставка; действует наибольшая version пары (participant_code, principal_ref). */
export interface LimitsRecordBody {
  participant_code: string;
  kid: string;
  version: number;
  limits: Limits;
  issued_at: string;
  /** base64url, 64 байта */
  signature: string;
}

export interface StateOp {
  mandate_id: string;
  op_ref: string;
  amount: number;
  reservation_id?: string;
}

export interface DealView {
  deal_ref?: string;
  status?: "AWAITING_FUNDING" | "FUNDED" | "RELEASED" | "RETURNED" | "PARTIAL" | "CANCELLED";
  amount?: number;
  currency?: string;
  payee_merchant_id?: string;
  valid_to?: string;
}

export interface DealOutcome {
  outcome: "RELEASED" | "RETURNED" | "PARTIAL";
  released_amount?: number;
  returned_amount?: number;
  at: string;
  evidence_hash?: string;
}

// Перечни значений: «СХЕМА_ПОЛЕ».
export const INSTRUMENT_KIND = ["AGENT_TOKEN","ACCOUNT_LINK","CARD_TOKEN"] as const;
export const CANONICAL_MESSAGE_MSG_TYPE = ["AUTH_REQUEST","ISSUER_RESPONSE","REVERSAL","PRESENTMENT","REFUND","CHARGEBACK","AUTH_EXPIRED"] as const;
export const CANONICAL_MESSAGE_CHANNEL = ["CARD","SBP"] as const;
export const DECISION_DECISION = ["APPROVE","DECLINE","CONFIRMATION_REQUIRED","BYPASS"] as const;
export const DECISION_REASON = ["AOI_MISSING","AOI_MISMATCH","AGENT_UNKNOWN","AGENT_SUSPENDED","CREDENTIAL_INVALID","MANDATE_NOT_FOUND","MANDATE_EXPIRED","MANDATE_REVOKED","MANDATE_SCOPE","LIMIT_EXCEEDED","STATE_UNAVAILABLE","CONFIRMATION_REQUIRED","ADP_UNAVAILABLE"] as const;
export const LIMITS_PERIOD = ["DAY","MONTH"] as const;
export const DEAL_VIEW_STATUS = ["AWAITING_FUNDING","FUNDED","RELEASED","RETURNED","PARTIAL","CANCELLED"] as const;
export const DEAL_OUTCOME_OUTCOME = ["RELEASED","RETURNED","PARTIAL"] as const;

/** components.schemas как в спецификации — для проверок в тестах. */
export const PI_SCHEMAS: Record<string, unknown> = {
  "Instrument": {
    "type": "object",
    "required": [
      "kind"
    ],
    "properties": {
      "kind": {
        "type": "string",
        "enum": [
          "AGENT_TOKEN",
          "ACCOUNT_LINK",
          "CARD_TOKEN"
        ]
      },
      "token_ref": {
        "type": "string"
      },
      "cryptogram": {
        "type": "string"
      },
      "account_link_ref": {
        "type": "string"
      },
      "issuer_id": {
        "type": "string"
      }
    }
  },
  "Merchant": {
    "type": "object",
    "properties": {
      "id": {
        "type": "string"
      },
      "mcc": {
        "type": "string"
      },
      "acquirer_id": {
        "type": "string"
      },
      "name": {
        "type": "string"
      }
    }
  },
  "Aoi": {
    "type": "object",
    "description": "Признак агентской операции (ПИ-2). Неагентская операция (ADP — BYPASS, мимо проверок): instrument.kind = CARD_TOKEN и признака нет — aoi нет, aoi: null или indicator: false без agent_code и mandate_id (нет или null); эквайрер может передавать поле признака во всех сообщениях (РП49 (в)). indicator: false с agent_code или mandate_id у CARD_TOKEN — противоречивый признак, агентская: DECLINE / CREDENTIAL_INVALID. Агентский инструмент (AGENT_TOKEN, ACCOUNT_LINK) — агентская при любом aoi; aoi без indicator — AOI_MISSING.",
    "properties": {
      "indicator": {
        "type": "boolean"
      },
      "agent_code": {
        "type": "string"
      },
      "mandate_id": {
        "type": "string"
      },
      "fulfilment_ref": {
        "type": "string",
        "nullable": true
      },
      "deal_ref": {
        "type": "string",
        "nullable": true
      }
    }
  },
  "CanonicalMessage": {
    "type": "object",
    "required": [
      "op_ref",
      "msg_type",
      "channel",
      "amount",
      "currency",
      "merchant",
      "instrument"
    ],
    "properties": {
      "op_ref": {
        "type": "string"
      },
      "msg_type": {
        "type": "string",
        "enum": [
          "AUTH_REQUEST",
          "ISSUER_RESPONSE",
          "REVERSAL",
          "PRESENTMENT",
          "REFUND",
          "CHARGEBACK",
          "AUTH_EXPIRED"
        ]
      },
      "seq": {
        "type": "integer"
      },
      "channel": {
        "type": "string",
        "enum": [
          "CARD",
          "SBP"
        ]
      },
      "amount": {
        "type": "integer"
      },
      "currency": {
        "type": "string"
      },
      "merchant": {
        "$ref": "#/components/schemas/Merchant"
      },
      "instrument": {
        "$ref": "#/components/schemas/Instrument"
      },
      "aoi": {
        "$ref": "#/components/schemas/Aoi"
      },
      "confirmation_ref": {
        "type": "string",
        "nullable": true
      },
      "order_ref": {
        "type": "string"
      },
      "reservation_id": {
        "type": "string",
        "nullable": true
      },
      "issuer_approved": {
        "type": "boolean",
        "nullable": true
      },
      "ts": {
        "type": "string",
        "format": "date-time"
      }
    }
  },
  "Decision": {
    "type": "object",
    "description": "Пары в ответе ADP (РП19): APPROVE, BYPASS — reason null; DECLINE — код ПИ §6, кроме CONFIRMATION_REQUIRED и ADP_UNAVAILABLE; CONFIRMATION_REQUIRED — reason CONFIRMATION_REQUIRED. ADP_UNAVAILABLE — только в решении процессинга при таймауте ADP (DECLINE / ADP_UNAVAILABLE). Несогласованная пара — отказ.",
    "required": [
      "decision",
      "decided_in_ms"
    ],
    "properties": {
      "decision": {
        "type": "string",
        "enum": [
          "APPROVE",
          "DECLINE",
          "CONFIRMATION_REQUIRED",
          "BYPASS"
        ]
      },
      "reason": {
        "type": "string",
        "nullable": true,
        "enum": [
          null,
          "AOI_MISSING",
          "AOI_MISMATCH",
          "AGENT_UNKNOWN",
          "AGENT_SUSPENDED",
          "CREDENTIAL_INVALID",
          "MANDATE_NOT_FOUND",
          "MANDATE_EXPIRED",
          "MANDATE_REVOKED",
          "MANDATE_SCOPE",
          "LIMIT_EXCEEDED",
          "STATE_UNAVAILABLE",
          "CONFIRMATION_REQUIRED",
          "ADP_UNAVAILABLE"
        ]
      },
      "split_detected": {
        "type": "boolean",
        "description": "Дробление по мандату в окне (РП44 п. 7): true — только у CONFIRMATION_REQUIRED по доле (операция не выше порога, но с одобрениями и записями «в работе» в окне split_window_sec по корневому INTENT их не меньше split_min_ops и сумма выше порога); false — у CONFIRMATION_REQUIRED по порогу одной операции; у прочих решений поля нет."
      },
      "reservation_id": {
        "type": "string",
        "nullable": true
      },
      "agent_level": {
        "type": "integer"
      },
      "mandate_left_after": {
        "type": "integer"
      },
      "decided_in_ms": {
        "type": "number"
      }
    }
  },
  "Limits": {
    "type": "object",
    "description": "Лимиты клиента (РП45 п. 1, 3). Суммы — целые ≥ 0 в минимальных единицах, парой с currency (ISO 4217, обязательна при любом поле суммы); per_period и period — только вместе; period — календарный период в часовом поясе client_limit_period_tz. Неизвестное поле или period — 422 LIMITS_UNSUPPORTED. per_operation — сумма > per_operation → LIMIT_EXCEEDED; per_period — второй счёт удержаний ядра, резерв тем же op_key после мандата; merchant_categories — MCC вне списка → MANDATE_SCOPE; confirm_above — клиентский порог подтверждения (меньшее с рыночным, РП44 п. 5).",
    "additionalProperties": false,
    "properties": {
      "per_operation": {
        "type": "integer",
        "minimum": 0
      },
      "per_period": {
        "type": "integer",
        "minimum": 0
      },
      "period": {
        "type": "string",
        "enum": [
          "DAY",
          "MONTH"
        ]
      },
      "merchant_categories": {
        "type": "array",
        "maxItems": 1000,
        "items": {
          "type": "string",
          "pattern": "^[0-9]{4}$"
        }
      },
      "confirm_above": {
        "type": "integer",
        "minimum": 0
      },
      "currency": {
        "type": "string",
        "pattern": "^[A-Z]{3}$"
      }
    }
  },
  "LimitsRecordBody": {
    "type": "object",
    "description": "Подписанная банком запись лимитов (РП45 п. 1). Подпись Ed25519 ключом банка над canonicalJson записи {context, participant_code, kid, principal_ref, version, limits, issued_at}; context = pao:participant-limits:v1, principal_ref — из пути. Только вставка; действует наибольшая version пары (participant_code, principal_ref).",
    "additionalProperties": false,
    "required": [
      "participant_code",
      "kid",
      "version",
      "limits",
      "issued_at",
      "signature"
    ],
    "properties": {
      "participant_code": {
        "type": "string"
      },
      "kid": {
        "type": "string"
      },
      "version": {
        "type": "integer",
        "minimum": 1
      },
      "limits": {
        "$ref": "#/components/schemas/Limits"
      },
      "issued_at": {
        "type": "string",
        "format": "date-time"
      },
      "signature": {
        "type": "string",
        "description": "base64url, 64 байта"
      }
    }
  },
  "StateOp": {
    "type": "object",
    "required": [
      "mandate_id",
      "op_ref",
      "amount"
    ],
    "properties": {
      "mandate_id": {
        "type": "string"
      },
      "op_ref": {
        "type": "string"
      },
      "amount": {
        "type": "integer"
      },
      "reservation_id": {
        "type": "string"
      }
    }
  },
  "DealView": {
    "type": "object",
    "properties": {
      "deal_ref": {
        "type": "string"
      },
      "status": {
        "type": "string",
        "enum": [
          "AWAITING_FUNDING",
          "FUNDED",
          "RELEASED",
          "RETURNED",
          "PARTIAL",
          "CANCELLED"
        ]
      },
      "amount": {
        "type": "integer"
      },
      "currency": {
        "type": "string"
      },
      "payee_merchant_id": {
        "type": "string"
      },
      "valid_to": {
        "type": "string",
        "format": "date-time"
      }
    }
  },
  "DealOutcome": {
    "type": "object",
    "required": [
      "outcome",
      "at"
    ],
    "properties": {
      "outcome": {
        "type": "string",
        "enum": [
          "RELEASED",
          "RETURNED",
          "PARTIAL"
        ]
      },
      "released_amount": {
        "type": "integer"
      },
      "returned_amount": {
        "type": "integer"
      },
      "at": {
        "type": "string",
        "format": "date-time"
      },
      "evidence_hash": {
        "type": "string"
      }
    }
  }
};
