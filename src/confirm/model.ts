// П6 Подтверждение человеком (SPEC §3, РП50): запрос подтверждения на итоговые значения и однократная ссылка
// confirmation_ref. Итог — из сообщения процессинга и записей Платформы (инвариант 5); номера карты нет (инвариант 1).
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { canonicalJson } from "@kuzin4u/agentic-core";

/**
 * Итоговые значения (РП50 п. 1): то, что видит и подтверждает человек. Они же — ключ запроса (п. 2) без агента: агент
 * известен по мандату, а в ссылке сверяется отдельно (п. 7).
 */
export interface ConfirmationTotals {
  readonly agent_code: string;
  readonly mandate_id: string;
  readonly merchant_id: string;
  /** Целое в минимальных единицах валюты (правило совместимости 2). */
  readonly amount: number;
  /** ISO 4217. */
  readonly currency: string;
  readonly order_ref: string;
}

/**
 * Статус записи (РП50 п. 5): PENDING → APPROVED | REJECTED | EXPIRED; APPROVED → USED. USED — внутренний, в перечне ПАО
 * его нет. Истечение PENDING — по часам Платформы при обращении (остаточный риск 4).
 */
export type ConfirmationStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "USED";

/** Решение человека, присланное участником (ПИ-8, РП50 п. 4): запись и подпись банка хранятся как доказательство. */
export interface ConfirmationDecision {
  readonly participant_code: string;
  readonly kid: string;
  readonly decision: "APPROVE" | "REJECT";
  readonly totals_hash: string;
  readonly decided_at: string;
  readonly signature: string;
}

export interface ConfirmationRecord extends ConfirmationTotals {
  readonly confirmation_id: string;
  /** Признак доли (РП44 п. 7) на момент запроса; в итоговые значения и totals_hash не входит (РП50 п. 4). */
  readonly split_detected: boolean;
  readonly status: ConfirmationStatus;
  readonly created_at: string;
  /** created_at + order_hold_sec по часам Платформы (РП50 п. 1). */
  readonly expires_at: string;
  /** Выдаётся при APPROVE (п. 6); у остальных — null. */
  readonly confirmation_ref: string | null;
  /** Решение участника; у PENDING и EXPIRED без решения — null. */
  readonly decision: ConfirmationDecision | null;
  /** Операция, погасившая ссылку (п. 10); у USED — обязательна. */
  readonly op_ref: string | null;
}

/** Метка подписи участника над решением человека (РП50 п. 4): подпись мандата или отзыва не подходит. */
export const PARTICIPANT_CONFIRMATION_CONTEXT = "pao:participant-confirmation:v1";

export const CONFIRMATION_ID = /^cnf_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** `cr_` + 26 знаков base32 (RFC 4648, строчные, без дополнения) из 128 бит — 29 знаков, поле ПИ-1 — до 32 (п. 6). */
export const CONFIRMATION_REF = /^cr_[a-z2-7]{26}$/;

export const newConfirmationId = (): string => `cnf_${randomUUID()}`;

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

/** 128 бит случайности в base32: 26 знаков, последний несёт 3 бита и 2 нулевых. */
export function newConfirmationRef(): string {
  const bytes = randomBytes(16);
  let bits = 0;
  let acc = 0;
  let s = "cr_";
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      s += BASE32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) s += BASE32[(acc << (5 - bits)) & 31];
  return s;
}

/**
 * totals_hash (РП50 п. 4): SHA-256 UTF-8 канонической записи RFC 8785 объекта {confirmation_id, agent_code, mandate_id,
 * merchant_id, amount, currency, order_ref}, 64 строчные hex. Для строк и целого RFC 8785 совпадает с canonicalJson ядра.
 */
export function totalsHash(r: ConfirmationTotals & { readonly confirmation_id: string }): string {
  const input = canonicalJson({
    confirmation_id: r.confirmation_id,
    agent_code: r.agent_code,
    mandate_id: r.mandate_id,
    merchant_id: r.merchant_id,
    amount: r.amount,
    currency: r.currency,
    order_ref: r.order_ref,
  });
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Итоговые значения совпадают поле в поле (РП50 п. 7). */
export const sameTotals = (a: ConfirmationTotals, b: ConfirmationTotals): boolean =>
  a.agent_code === b.agent_code &&
  a.mandate_id === b.mandate_id &&
  a.merchant_id === b.merchant_id &&
  a.amount === b.amount &&
  a.currency === b.currency &&
  a.order_ref === b.order_ref;

/** Байты подписи участника: canonicalJson записи решения с меткой контекста и confirmation_id из пути, UTF-8. */
export const participantConfirmationSigningInput = (
  r: Omit<ConfirmationDecision, "signature"> & { readonly confirmation_id: string },
): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_CONFIRMATION_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      confirmation_id: r.confirmation_id,
      decision: r.decision,
      totals_hash: r.totals_hash,
      decided_at: r.decided_at,
    }),
    "utf8",
  );
