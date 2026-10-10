// Сгенерировано scripts/gen-shared.mjs из docs/core/processing-interface.yaml — не править вручную.
// Интерфейсы Платформы с процессингом и участниками 1.0.0-draft, sha-256 6cb50db5e49678e02cc5d458557778eaccd8008cbde54e0460d6137daa29088e
// Номера полей и кодов внешних форматов здесь нет: только каноническая модель [альбом] (РП6).

export const PI_VERSION = "1.0.0-draft";
export const PI_SPEC_SHA256 = "6cb50db5e49678e02cc5d458557778eaccd8008cbde54e0460d6137daa29088e";

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
  split_detected?: boolean;
  reservation_id?: string | null;
  agent_level?: number;
  mandate_left_after?: number;
  decided_in_ms: number;
}

export interface Limits {
  per_operation?: number;
  per_period?: number;
  period?: string;
  merchant_categories?: Array<string>;
  confirm_above?: number;
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
        "type": "boolean"
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
    "properties": {
      "per_operation": {
        "type": "integer"
      },
      "per_period": {
        "type": "integer"
      },
      "period": {
        "type": "string"
      },
      "merchant_categories": {
        "type": "array",
        "items": {
          "type": "string"
        }
      },
      "confirm_above": {
        "type": "integer"
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
