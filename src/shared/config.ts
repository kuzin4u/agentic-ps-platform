// Стендовые параметры Платформы (docs/core/PARAMS.md). В коде значений нет — только из файла.
// Читается через fs при запуске: tsconfig.build.json собирает только src/.
// Fail-closed: отсутствующий, лишний или неверный ключ — отказ запуска, значений по умолчанию нет.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export const DEFAULT_PARAMS_PATH = "config/params.stand.json";

/** Режимы эмитента (РП3, GLOSSARY). */
export const ISSUER_MODES = ["ON_BEHALF", "ISSUER_SIDE"] as const;
export type IssuerMode = (typeof ISSUER_MODES)[number];

export interface Params {
  readonly adp_p99_ms: number;
  readonly adp_timeout_ms: number;
  readonly bypass_overhead_ms: number;
  /** Процент, из строки вида "99.95%". */
  readonly adp_availability_target: number;
  readonly revocation_propagation_max_ms: number;
  readonly reservation_ttl_sec: number;
  readonly event_reorder_window_ms: number;
  readonly event_retry_max: number;
  readonly cryptogram_ttl_sec: number;
  readonly order_hold_sec: number;
  readonly confirm_above_kop: number;
  readonly split_window_sec: number;
  readonly split_min_ops: number;
  readonly signature_skew_sec: number;
  readonly key_ttl_days: number;
  readonly key_overlap_days: number;
  readonly qualified_signature_above_kop: number;
  readonly qualified_signature_above_days: number;
  readonly restore_budget_on_refund: boolean;
  readonly aoi_rollout_phase: 1 | 2 | 3;
  readonly protocol_overlap_days: number;
  readonly issuer_mode_default: IssuerMode;
  readonly cx_outcome_timeout_days: number;
}

type Rule = (v: unknown) => unknown;

const int =
  (min: number, max = Number.MAX_SAFE_INTEGER): Rule =>
  (v) => {
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
      throw new Error(`ожидается целое ${min}…${max}`);
    }
    return v;
  };

const bool: Rule = (v) => {
  if (typeof v !== "boolean") throw new Error("ожидается true или false");
  return v;
};

const oneOf =
  (values: readonly string[]): Rule =>
  (v) => {
    if (typeof v !== "string" || !values.includes(v)) throw new Error(`ожидается одно из ${values.join(", ")}`);
    return v;
  };

const percent: Rule = (v) => {
  const m = typeof v === "string" ? /^(\d{1,3}(?:\.\d+)?)%$/.exec(v) : null;
  const n = m ? Number(m[1]) : NaN;
  if (!(n > 0 && n <= 100)) throw new Error('ожидается процент вида "99.95%"');
  return n;
};

const RULES: Record<keyof Params, Rule> = {
  adp_p99_ms: int(1),
  adp_timeout_ms: int(1),
  bypass_overhead_ms: int(0),
  adp_availability_target: percent,
  revocation_propagation_max_ms: int(1),
  reservation_ttl_sec: int(1),
  event_reorder_window_ms: int(0),
  event_retry_max: int(0),
  cryptogram_ttl_sec: int(1),
  order_hold_sec: int(1),
  confirm_above_kop: int(1),
  split_window_sec: int(1),
  split_min_ops: int(2),
  signature_skew_sec: int(1),
  key_ttl_days: int(1),
  key_overlap_days: int(0),
  qualified_signature_above_kop: int(1),
  qualified_signature_above_days: int(1),
  restore_budget_on_refund: bool,
  aoi_rollout_phase: int(1, 3),
  protocol_overlap_days: int(0),
  issuer_mode_default: oneOf(ISSUER_MODES),
  cx_outcome_timeout_days: int(1),
};

/** Служебные ключи файла, не параметры. */
const SERVICE_KEYS = new Set(["_comment"]);

export class ParamsError extends Error {
  constructor(readonly problems: readonly string[]) {
    super(`Стендовые параметры неверны: ${problems.join("; ")}`);
    this.name = "ParamsError";
  }
}

export function parseParams(raw: unknown): Params {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ParamsError(["ожидается объект"]);
  const src = raw as Record<string, unknown>;
  const problems: string[] = [];
  const out: Record<string, unknown> = {};
  for (const [k, rule] of Object.entries(RULES)) {
    if (!(k in src)) {
      problems.push(`${k}: нет ключа`);
      continue;
    }
    try {
      out[k] = rule(src[k]);
    } catch (e) {
      problems.push(`${k}: ${(e as Error).message}`);
    }
  }
  for (const k of Object.keys(src)) {
    if (!(k in RULES) && !SERVICE_KEYS.has(k)) problems.push(`${k}: неизвестный ключ`);
  }
  if (problems.length === 0) {
    const p = out as unknown as Params;
    if (p.adp_timeout_ms < p.adp_p99_ms) problems.push("adp_timeout_ms меньше adp_p99_ms");
    if (p.key_overlap_days >= p.key_ttl_days) problems.push("key_overlap_days не меньше key_ttl_days");
  }
  if (problems.length) throw new ParamsError(problems);
  return Object.freeze(out) as unknown as Params;
}

export function loadParams(path = process.env.PARAMS_PATH ?? DEFAULT_PARAMS_PATH): Params {
  const full = resolve(path);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(full, "utf8"));
  } catch (e) {
    throw new ParamsError([`${full}: ${(e as Error).message}`]);
  }
  return parseParams(raw);
}
