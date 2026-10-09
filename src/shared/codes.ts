// Коды решений ADP (SPEC §6, ПИ §6) и ошибок ПАО (x-pao-errors, РП16).
// Перечни — из сгенерированных файлов; неизвестный код — отказ (инвариант 3, A3 п. 4.5).
import { DECISION_DECISION, DECISION_REASON } from "./canonical.generated.js";
import { PAO_ERRORS, PAO_ERROR_CODES, type PaoErrorCode, type PaoErrorSpec } from "./pao-errors.generated.js";

export const DECISIONS = DECISION_DECISION;
export type DecisionKind = (typeof DECISIONS)[number];

/** Коды причин отказа и подтверждения; номера кодов ответа ОПКЦ — [альбом]. */
export const DECISION_REASONS = DECISION_REASON;
export type DecisionReason = (typeof DECISION_REASONS)[number];

export class UnknownCodeError extends Error {
  constructor(
    readonly kind: string,
    readonly value: unknown,
  ) {
    super(`Неизвестный код ${kind}: ${JSON.stringify(value)}`);
    this.name = "UnknownCodeError";
  }
}

const has = <T extends string>(list: readonly T[], v: unknown): v is T =>
  typeof v === "string" && (list as readonly string[]).includes(v);

export const isDecisionKind = (v: unknown): v is DecisionKind => has(DECISIONS, v);
export const isDecisionReason = (v: unknown): v is DecisionReason => has(DECISION_REASONS, v);
export const isPaoErrorCode = (v: unknown): v is PaoErrorCode => has(PAO_ERROR_CODES, v);

export function parseDecisionKind(v: unknown): DecisionKind {
  if (!isDecisionKind(v)) throw new UnknownCodeError("решения", v);
  return v;
}

export function parseDecisionReason(v: unknown): DecisionReason {
  if (!isDecisionReason(v)) throw new UnknownCodeError("причины", v);
  return v;
}

const BY_CODE = new Map<string, PaoErrorSpec>(PAO_ERRORS.map((e) => [e.code, e]));

/** Запись таблицы ошибок ПАО: HTTP и retry. Неизвестный код — исключение, не догадка. */
export function paoError(code: unknown): PaoErrorSpec {
  const spec = typeof code === "string" ? BY_CODE.get(code) : undefined;
  if (!spec) throw new UnknownCodeError("ошибки ПАО", code);
  return spec;
}
