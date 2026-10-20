// Стендовые параметры Платформы (docs/core/PARAMS.md). В коде значений нет — только из файла.
// Читается через fs при запуске: tsconfig.build.json собирает только src/.
// Fail-closed: отсутствующий, лишний или неверный ключ, нарушенная граница — отказ запуска, значений по умолчанию нет.
// Границы и перекрёстные правила — PARAMS.md «Границы» (РП20).
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const DEFAULT_PARAMS_PATH = "config/params.stand.json";
// От корня пакета Платформы, а не от текущего каталога: стенд в чужом репозитории читает свои параметры (РП25).
// src/shared/config.ts и dist/shared/config.js лежат на одной глубине от корня.
const PACKAGE_ROOT = fileURLToPath(new URL("../../", import.meta.url));

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
  /** Не больше стольких событий в ответе GET /pao/v1/events (РП39 п. 7). */
  readonly event_page_max: number;
  /** Тайм-аут одной попытки push-доставки события, мс (РП40 п. 4). */
  readonly event_delivery_timeout_ms: number;
  /** Разрешённые хосты адреса подписки; пустой — подписка запрещена всем (РП40 п. 2). */
  readonly event_subscription_allow_hosts: readonly string[];
  readonly cryptogram_ttl_sec: number;
  readonly order_hold_sec: number;
  readonly confirm_above_kop: number;
  readonly split_window_sec: number;
  readonly split_min_ops: number;
  readonly signature_skew_sec: number;
  /** Retry-After у ответов ПАО 503; 0…30 — не больше maxRetryAfterSec клиента agentic-core (РП24). */
  readonly unavailable_retry_after_sec: number;
  /** Лимит обращений к витринам эмулятора продавцов с одного адреса в минуту (PS-12); на стенде — щедрый. */
  readonly merchant_rate_limit_per_min: number;
  /** Срок хранения результата идемпотентности ПАО, с; ≥ 60 — не меньше аренды захвата ядра (РП30 п. 3). */
  readonly idempotency_ttl_sec: number;
  readonly pao_rate_limit_per_30s: number;
  readonly key_ttl_days: number;
  readonly key_overlap_days: number;
  readonly qualified_signature_above_kop: number;
  readonly qualified_signature_above_days: number;
  readonly restore_budget_on_refund: boolean;
  readonly aoi_rollout_phase: 1 | 2 | 3;
  readonly protocol_overlap_days: number;
  readonly issuer_mode_default: IssuerMode;
  readonly cx_outcome_timeout_days: number;
  /** Часовой пояс календарного периода лимита клиента DAY/MONTH (IANA, РП45 п. 1). */
  readonly client_limit_period_tz: string;
  /** Наибольшая задержка уведомления клиента через банк по решению ADP, с (РП46 доп. п. 7): период прохода уведомителя. */
  readonly participant_notify_max_delay_sec: number;
  /** Горизонт прохода уведомителя по записям операций, с (РП46 доп. п. 9 (о2)): старше — не разбираются. */
  readonly participant_notify_horizon_sec: number;
  /** Разрешённые хосты адреса вебхука участника (РП46 доп. п. 9 (о4)); пустой — вебхук запрещён всем. */
  readonly participant_notify_allow_hosts: readonly string[];
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

const DNS_NAME = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/;
const IPV4_LIKE = /^[0-9.]+$/;

const hostList: Rule = (v) => {
  if (!Array.isArray(v)) throw new Error("ожидается массив имён хостов");
  for (const h of v) {
    if (typeof h !== "string" || !DNS_NAME.test(h) || IPV4_LIKE.test(h)) {
      throw new Error(`ожидается имя DNS в нижнем регистре, не IP: ${String(h)}`);
    }
  }
  if (new Set(v).size !== v.length) throw new Error("имена хостов повторяются");
  return Object.freeze([...v]);
};

/** Имя часового пояса IANA, известное Intl (РП45 п. 1): неизвестное — отказ запуска, а не UTC по умолчанию. */
const timeZone: Rule = (v) => {
  if (typeof v !== "string" || !/^[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+)*$/.test(v)) throw new Error("ожидается имя часового пояса IANA");
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: v });
  } catch {
    throw new Error(`неизвестный часовой пояс ${v}`);
  }
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
  event_retry_max: int(1),
  event_page_max: int(1),
  event_delivery_timeout_ms: int(1),
  event_subscription_allow_hosts: hostList,
  cryptogram_ttl_sec: int(1),
  order_hold_sec: int(1),
  confirm_above_kop: int(1),
  split_window_sec: int(1),
  split_min_ops: int(2),
  signature_skew_sec: int(1),
  unavailable_retry_after_sec: int(0, 30),
  merchant_rate_limit_per_min: int(1),
  idempotency_ttl_sec: int(60),
  pao_rate_limit_per_30s: int(1),
  key_ttl_days: int(1),
  key_overlap_days: int(0),
  qualified_signature_above_kop: int(1),
  qualified_signature_above_days: int(1),
  restore_budget_on_refund: bool,
  aoi_rollout_phase: int(1, 3),
  protocol_overlap_days: int(1),
  issuer_mode_default: oneOf(ISSUER_MODES),
  cx_outcome_timeout_days: int(1),
  client_limit_period_tz: timeZone,
  participant_notify_max_delay_sec: int(1),
  participant_notify_horizon_sec: int(1),
  participant_notify_allow_hosts: hostList,
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
    if (!Object.hasOwn(src, k)) {
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
    if (!Object.hasOwn(RULES, k) && !SERVICE_KEYS.has(k)) problems.push(`${k}: неизвестный ключ`);
  }
  if (problems.length === 0) {
    const p = out as unknown as Params;
    if (p.adp_timeout_ms <= p.adp_p99_ms) problems.push("adp_timeout_ms не больше adp_p99_ms");
    if (p.bypass_overhead_ms >= p.adp_p99_ms) problems.push("bypass_overhead_ms не меньше adp_p99_ms");
    if (p.key_overlap_days >= p.key_ttl_days) problems.push("key_overlap_days не меньше key_ttl_days");
    // Признак отставания — половина горизонта (РП46 доп. п. 9 (о2)); она не короче наибольшей задержки уведомления.
    if (p.participant_notify_horizon_sec < 2 * p.participant_notify_max_delay_sec) {
      problems.push("participant_notify_horizon_sec меньше двух participant_notify_max_delay_sec");
    }
  }
  if (problems.length) throw new ParamsError(problems);
  return Object.freeze(out) as unknown as Params;
}

export function loadParams(path = process.env.PARAMS_PATH ?? resolve(PACKAGE_ROOT, DEFAULT_PARAMS_PATH)): Params {
  const full = resolve(path);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(full, "utf8"));
  } catch (e) {
    throw new ParamsError([`${full}: ${(e as Error).message}`]);
  }
  return parseParams(raw);
}
