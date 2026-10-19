// П10 Лимиты клиента от банка (ПИ-8 `PUT /participants/v1/principals/{ref}/limits`, РП45 п. 1, 3): подписанная запись
// банка с версией, только вставка; действует наибольшая версия пары «банк + клиент». В памяти (dev без базы, стенд) и на
// PostgreSQL (sql/105_participant_limits.sql). Номера карты нет — только principal_ref (инвариант 1).
import { canonicalJson, isCurrencyCode, type SqlClient } from "@kuzin4u/agentic-core";
import { parseRfc3339 } from "../consent/model.js";
import { isOpaquePrincipalRef } from "../consent/terms.js";

/** Метка контекста подписи лимитов (РП45 п. 1): подпись решения или отзыва как лимиты не годится, и наоборот. */
export const PARTICIPANT_LIMITS_CONTEXT = "pao:participant-limits:v1";

export const LIMIT_PERIODS = ["DAY", "MONTH"] as const;
export type LimitPeriod = (typeof LIMIT_PERIODS)[number];

/** Limits ПИ-8: суммы — целые ≥ 0 в минимальных единицах, парой с currency (правило совместимости 2). */
export interface ClientLimits {
  readonly per_operation?: number;
  readonly per_period?: number;
  readonly period?: LimitPeriod;
  readonly merchant_categories?: readonly string[];
  readonly confirm_above?: number;
  readonly currency?: string;
}

/** Подписываемая банком запись лимитов; метка контекста добавляется при подписи. */
export interface LimitsRecord {
  readonly participant_code: string;
  readonly kid: string;
  readonly principal_ref: string;
  readonly version: number;
  readonly limits: ClientLimits;
  readonly issued_at: string;
}

/** Запись в хранилище: подпись банка — доказательство, received_at — часы Платформы. */
export interface StoredLimits extends LimitsRecord {
  readonly signature: string;
  readonly received_at: string;
}

/** Клиент мандата (РП45 п. 1): банк, подписавший мандат (у CART — корневой INTENT), и principal_ref записи мандата. */
export interface ClientRef {
  readonly participant_code: string;
  readonly principal_ref: string;
}

const LIMIT_FIELDS = new Set(["per_operation", "per_period", "period", "merchant_categories", "confirm_above", "currency"]);
const AMOUNT_FIELDS = ["per_operation", "per_period", "confirm_above"] as const;
const MCC = /^[0-9]{4}$/;

export type LimitsParse = { readonly ok: true; readonly limits: ClientLimits } | { readonly ok: false; readonly code: "REQUEST_INVALID" | "LIMITS_UNSUPPORTED" };

const isAmount = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/**
 * Limits по ПИ-8 (РП45 п. 3): неизвестное поле или period — LIMITS_UNSUPPORTED (неприменённое ограничение клиента было бы
 * обходом, инвариант 3); сумма без валюты, per_period без period и наоборот, не целое ≥ 0 — REQUEST_INVALID.
 */
export function parseLimits(v: unknown): LimitsParse {
  const bad = { ok: false, code: "REQUEST_INVALID" } as const;
  if (typeof v !== "object" || v === null || Array.isArray(v)) return bad;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).some((k) => !LIMIT_FIELDS.has(k))) return { ok: false, code: "LIMITS_UNSUPPORTED" };
  if (o.period !== undefined && !(LIMIT_PERIODS as readonly unknown[]).includes(o.period)) {
    return typeof o.period === "string" ? { ok: false, code: "LIMITS_UNSUPPORTED" } : bad;
  }
  for (const k of AMOUNT_FIELDS) if (o[k] !== undefined && !isAmount(o[k])) return bad;
  const amounts = AMOUNT_FIELDS.some((k) => o[k] !== undefined);
  if (o.currency !== undefined && !isCurrencyCode(o.currency)) return bad;
  if (amounts && o.currency === undefined) return bad;
  if ((o.per_period === undefined) !== (o.period === undefined)) return bad;
  const mcc = o.merchant_categories;
  if (mcc !== undefined && (!Array.isArray(mcc) || mcc.length > 1000 || !mcc.every((c) => typeof c === "string" && MCC.test(c)))) return bad;
  // Запись — как прислал банк, без нормализации: подпись и доказательство — над теми же байтами canonicalJson.
  return { ok: true, limits: structuredClone(o) as ClientLimits };
}

const RECORD_FIELDS = ["issued_at", "kid", "limits", "participant_code", "signature", "version"].join(",");

export type LimitsBody = { readonly ok: true; readonly record: LimitsRecord; readonly signature: string } | Extract<LimitsParse, { ok: false }>;

/** Тело PUT: ровно поля записи без principal_ref (он в пути) и подпись; лишнее поле не подписано — отказ, а не пропуск. */
export function limitsBody(principal_ref: string, v: unknown): LimitsBody {
  const bad = { ok: false, code: "REQUEST_INVALID" } as const;
  if (!isOpaquePrincipalRef(principal_ref)) return bad;
  if (typeof v !== "object" || v === null || Array.isArray(v)) return bad;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== RECORD_FIELDS) return bad;
  const str = (k: string) => typeof o[k] === "string" && (o[k] as string).length > 0 && (o[k] as string).length <= 256;
  if (!["participant_code", "kid", "signature", "issued_at"].every(str)) return bad;
  if (Number.isNaN(parseRfc3339(o.issued_at))) return bad;
  if (typeof o.version !== "number" || !Number.isSafeInteger(o.version) || o.version < 1) return bad;
  const limits = parseLimits(o.limits);
  if (!limits.ok) return limits;
  return {
    ok: true,
    record: {
      participant_code: o.participant_code as string,
      kid: o.kid as string,
      principal_ref,
      version: o.version,
      limits: limits.limits,
      issued_at: o.issued_at as string,
    },
    signature: o.signature as string,
  };
}

/** Байты подписи: canonicalJson записи с меткой контекста, UTF-8 (как у решения и отзыва, РП36 доп. п. 2). */
export const participantLimitsSigningInput = (r: LimitsRecord): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_LIMITS_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      principal_ref: r.principal_ref,
      version: r.version,
      limits: r.limits,
      issued_at: r.issued_at,
    }),
    "utf8",
  );

export type LimitsPut = "inserted" | "replayed" | "conflict";

/** Хранилище записей лимитов; сбой — исключение (→ 503 у банка, STATE_UNAVAILABLE у ADP). */
export interface LimitsStore {
  /**
   * Только вставка: версия выше действующей — inserted; та же версия с той же записью и подписью — replayed; та же
   * версия с другой записью или версия не выше действующей — conflict (LIMITS_VERSION_CONFLICT).
   */
  put(rec: StoredLimits): Promise<LimitsPut>;
  /** Действующая запись пары — наибольшая версия; записи нет — undefined. */
  current(client: ClientRef): Promise<StoredLimits | undefined>;
  /** Все версии пары по возрастанию version — для правила «расширение со следующего периода» (РП45 п. 1). */
  history(client: ClientRef): Promise<readonly StoredLimits[]>;
}

/** Та же запись: реквизиты и подпись (Ed25519 детерминирована — повтор банка даёт ту же подпись). */
const sameRecord = (a: StoredLimits, b: StoredLimits): boolean =>
  a.kid === b.kid && a.issued_at === b.issued_at && a.signature === b.signature && canonicalJson(a.limits) === canonicalJson(b.limits);

const clientKey = (c: ClientRef): string => `${c.participant_code}\n${c.principal_ref}`;

export class MemoryLimitsStore implements LimitsStore {
  readonly #rows = new Map<string, StoredLimits[]>();

  async put(rec: StoredLimits): Promise<LimitsPut> {
    const rows = this.#rows.get(clientKey(rec)) ?? [];
    const same = rows.find((r) => r.version === rec.version);
    if (same) return sameRecord(same, rec) ? "replayed" : "conflict";
    if (rows.some((r) => r.version > rec.version)) return "conflict";
    rows.push(structuredClone(rec));
    this.#rows.set(clientKey(rec), rows);
    return "inserted";
  }

  async current(client: ClientRef): Promise<StoredLimits | undefined> {
    const rows = this.#rows.get(clientKey(client));
    if (!rows || rows.length === 0) return undefined;
    return structuredClone(rows.reduce((a, b) => (b.version > a.version ? b : a)));
  }

  async history(client: ClientRef): Promise<readonly StoredLimits[]> {
    return structuredClone([...(this.#rows.get(clientKey(client)) ?? [])].sort((a, b) => a.version - b.version));
  }
}

interface LimitsRow extends Record<string, unknown> {
  participant_code: string;
  principal_ref: string;
  version: string;
  kid: string;
  limits: ClientLimits;
  issued_at: string;
  signature: string;
  received_at: string;
}

const fromRow = (r: LimitsRow): StoredLimits => ({
  participant_code: r.participant_code,
  kid: r.kid,
  principal_ref: r.principal_ref,
  version: Number(r.version),
  limits: r.limits,
  issued_at: r.issued_at,
  signature: r.signature,
  received_at: r.received_at,
});

/**
 * Записи лимитов на PostgreSQL: вставка одним оператором — только если нет версии не ниже (ON CONFLICT по версии —
 * сверка с записанной). Одновременные вставки разных версий на двух экземплярах могут записать обе — действует
 * наибольшая, так что ADP мягкую старую не применит; ответ банку по младшей — inserted (остаточный риск, РП45).
 */
export class PgLimitsStore implements LimitsStore {
  constructor(private readonly client: SqlClient) {}

  async put(rec: StoredLimits): Promise<LimitsPut> {
    const ins = await this.client.query(
      `INSERT INTO participant_limits (participant_code, principal_ref, version, kid, limits, issued_at, signature, received_at)
       SELECT $1, $2, $3, $4, $5::jsonb, $6, $7, $8
        WHERE NOT EXISTS (SELECT 1 FROM participant_limits WHERE participant_code = $1 AND principal_ref = $2 AND version >= $3)
       ON CONFLICT (participant_code, principal_ref, version) DO NOTHING
       RETURNING version`,
      [rec.participant_code, rec.principal_ref, rec.version, rec.kid, JSON.stringify(rec.limits), rec.issued_at, rec.signature, rec.received_at],
    );
    if (ins.rows.length === 1) return "inserted";
    const r = await this.client.query<LimitsRow>(
      `SELECT participant_code, principal_ref, version, kid, limits, issued_at, signature, received_at
         FROM participant_limits WHERE participant_code = $1 AND principal_ref = $2 AND version = $3`,
      [rec.participant_code, rec.principal_ref, rec.version],
    );
    const same = r.rows[0];
    return same && sameRecord(fromRow(same), rec) ? "replayed" : "conflict";
  }

  async current(client: ClientRef): Promise<StoredLimits | undefined> {
    const r = await this.client.query<LimitsRow>(
      `SELECT participant_code, principal_ref, version, kid, limits, issued_at, signature, received_at
         FROM participant_limits WHERE participant_code = $1 AND principal_ref = $2 ORDER BY version DESC LIMIT 1`,
      [client.participant_code, client.principal_ref],
    );
    const row = r.rows[0];
    return row && fromRow(row);
  }

  async history(client: ClientRef): Promise<readonly StoredLimits[]> {
    const r = await this.client.query<LimitsRow>(
      `SELECT participant_code, principal_ref, version, kid, limits, issued_at, signature, received_at
         FROM participant_limits WHERE participant_code = $1 AND principal_ref = $2 ORDER BY version`,
      [client.participant_code, client.principal_ref],
    );
    return r.rows.map(fromRow);
  }
}

/**
 * Начало календарного периода в часовом поясе (РП45 п. 1): DAY — `YYYY-MM-DD`, MONTH — `YYYY-MM`; часы — Платформы.
 * Конец периода (срок удержания сужения, часть 2) — следующее начало.
 */
export function periodStart(period: LimitPeriod, tz: string, now: Date): string {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(now);
  const get = (t: string) => parts.find((p) => p.type === t)?.value;
  const y = get("year");
  const m = get("month");
  const d = get("day");
  if (!y || !m || !d) throw new Error(`periodStart: дата не вычислена в поясе ${tz}`);
  return period === "DAY" ? `${y}-${m}-${d}` : `${y}-${m}`;
}

/** Лимит за период, действующий для счёта клиента: предел парой с валютой и вид периода. */
export interface PeriodLimit {
  readonly per_period: number;
  readonly period: LimitPeriod;
  readonly currency: string;
}

const periodLimitOf = (l: ClientLimits): PeriodLimit | undefined =>
  l.per_period !== undefined && l.period !== undefined && l.currency !== undefined
    ? { per_period: l.per_period, period: l.period, currency: l.currency }
    : undefined;

/**
 * Действующий лимит за период по истории версий (РП45 п. 1, решение владельца по /audit № 1): версия, которая снимает
 * per_period или меняет period либо валюту, — расширение: действует с начала следующего периода прежнего вида, а до
 * того — прежний лимит. Новый per_period там, где его не было, и смена суммы при том же виде — сразу (сужение и
 * расширение суммы решает счёт периода, StateService.reserveClient). versions — по возрастанию version.
 */
export function effectivePeriodLimit(
  versions: readonly { readonly limits: ClientLimits; readonly received_at: string }[],
  tz: string,
  now: Date,
): PeriodLimit | undefined {
  let eff: PeriodLimit | undefined;
  for (const v of versions) {
    const next = periodLimitOf(v.limits);
    if (eff === undefined || (next && next.period === eff.period && next.currency === eff.currency)) {
      eff = next;
      continue;
    }
    // Снятие или смена вида — со следующего периода прежнего вида: в периоде получения версии действует прежний.
    if (periodStart(eff.period, tz, now) !== periodStart(eff.period, tz, new Date(v.received_at))) eff = next;
  }
  return eff;
}

