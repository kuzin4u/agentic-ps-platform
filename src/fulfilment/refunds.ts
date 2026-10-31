// П8 Возврат (РП55 п. 3–4, PS-16 ч. 3; РП71, PS-23 ч. 1): по ПИ-3 REFUND после записи об исполнении — запись (только
// вставка) и operation.refunded при первом возврате операции в одной транзакции. Без refund_ref — одна запись на op_ref
// (РП55 п. 3); с refund_ref — на пару (op_ref, refund_ref); первый возврат задаёт форму, смешение — без записи (РП71
// нюанс 1). Бюджет мандата не восстанавливается (restore_budget_on_refund = false, РП9; true — отказ запуска): в П3
// действий нет. В памяти (dev, стенд) и на PostgreSQL (sql/117, sql/122). Номера карты и token_ref нет (инвариант 1).
import { createHash } from "node:crypto";
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { OperationReader } from "../adp/operations.js";
import { insertOperationEventTx, type MemoryConsentStore, type TxSqlPool } from "../consent/store.js";
import type { OperationEventDraft } from "../pao/events.js";
import type { CollectorLog, IssuerResponseStatus, OutcomeStore, PushFor } from "./outcomes.js";
import { awaitPredecessor, type FulfilmentStore } from "./records.js";
import type { ReversalStore } from "./reversals.js";

export interface RefundRecord {
  readonly op_ref: string;
  /** Ссылка возврата у процессинга (РП71 п. 1); null — прежняя форма, один возврат на op_ref (РП55 п. 3). */
  readonly refund_ref: string | null;
  /** Агент по домену токена из записи ADP; null — не установлен: запись есть, события нет. */
  readonly agent_code: string | null;
  readonly mandate_id: string | null;
  /** Сумма возврата из сообщения процессинга — парой с валютой (правило 2 «Запад»). */
  readonly amount: number;
  readonly currency: string;
  readonly at: string;
}

/** operation.refunded — только агенту из домена токена; data — только {op_ref} (РП55 п. 3, A7 п. 8.3). */
export async function refundedEventFor(r: RefundRecord, pushFor?: PushFor): Promise<OperationEventDraft | undefined> {
  if (r.agent_code === null) return undefined;
  return { agent_code: r.agent_code, type: "operation.refunded", data: { op_ref: r.op_ref }, push: (await pushFor?.(r.agent_code, "operation.refunded")) ?? false };
}

/**
 * Исход записи возврата (РП71 п. 2–3, нюанс 1). inserted — записан; all — возвраты операции после вставки (по порядку
 * записи), событие записано только у первого. duplicate — тот же ключ с той же суммой и валютой (повтор). conflict — тот
 * же ключ с другой суммой или валютой: запись прежняя. mixed — у операции возвраты другой формы: без записи.
 */
export type RefundOutcome =
  | { readonly kind: "inserted"; readonly all: readonly RefundRecord[] }
  | { readonly kind: "duplicate"; readonly prior: RefundRecord }
  | { readonly kind: "conflict"; readonly prior: RefundRecord }
  | { readonly kind: "mixed"; readonly first: RefundRecord };

/**
 * Решение по возвратам операции (по порядку записи) до вставки: undefined — вставлять. Ключ — op_ref без ссылки или пара
 * (op_ref, refund_ref); форму задаёт первый возврат операции (нюанс 1). Общее для памяти и PG.
 */
export function classifyRefund(rows: readonly RefundRecord[], r: RefundRecord): Exclude<RefundOutcome, { kind: "inserted" }> | undefined {
  const first = rows[0];
  if (!first) return undefined;
  if ((first.refund_ref === null) !== (r.refund_ref === null)) return { kind: "mixed", first };
  const same = rows.find((x) => x.refund_ref === r.refund_ref);
  if (!same) return undefined;
  return same.amount === r.amount && same.currency === r.currency ? { kind: "duplicate", prior: same } : { kind: "conflict", prior: same };
}

/** Сбой любого метода — исключение. */
export interface RefundStore {
  /**
   * Атомарно по операции: сверка с возвратами операции (classifyRefund), вставка и — только если возвратов операции не
   * было — событие (РП71 п. 5).
   */
  record(r: RefundRecord, event: OperationEventDraft | undefined): Promise<RefundOutcome>;
  /** Первый возврат операции (по порядку записи) — для GET (REFUNDED). */
  get(op_ref: string): Promise<RefundRecord | undefined>;
  /** Все возвраты операции по порядку записи. */
  list(op_ref: string): Promise<RefundRecord[]>;
}

/** В памяти (dev, стенд): сверка, событие и запись — один синхронный шаг (событие первым, как запись об исполнении). */
export class MemoryRefundStore implements RefundStore {
  readonly #rows = new Map<string, RefundRecord[]>();

  constructor(private readonly events?: Pick<MemoryConsentStore, "appendOperationEventNow">) {}

  async record(r: RefundRecord, event: OperationEventDraft | undefined): Promise<RefundOutcome> {
    const rows = this.#rows.get(r.op_ref) ?? [];
    const decided = classifyRefund(rows, r);
    if (decided) return structuredClone(decided);
    // Без await между сверкой, событием и записью: сбой события оставляет операцию без записи — повтор ПИ-3 запишет.
    if (event && rows.length === 0) this.events?.appendOperationEventNow(event, r.at);
    const next = [...rows, Object.freeze({ ...r })];
    this.#rows.set(r.op_ref, next);
    return { kind: "inserted", all: next.map((x) => ({ ...x })) };
  }

  async get(op_ref: string): Promise<RefundRecord | undefined> {
    const r = this.#rows.get(op_ref)?.[0];
    return r && { ...r };
  }

  async list(op_ref: string): Promise<RefundRecord[]> {
    return (this.#rows.get(op_ref) ?? []).map((x) => ({ ...x }));
  }
}

const COLUMNS = "op_ref, refund_ref, agent_code, mandate_id, amount, currency, at";
const REFUND_LOCK_DOMAIN = "fulfilment:refund-lock:v1";

/** Ключ pg_advisory_xact_lock возвратов операции (РП71 нюанс 2): 64 бита SHA-256 со знаком, как splitWindowLockKey. */
export function refundLockKey(op_ref: string): string {
  return createHash("sha256").update(`${REFUND_LOCK_DOMAIN}\n${op_ref}`, "utf8").digest().readBigInt64BE(0).toString();
}

interface RefundRow extends Record<string, unknown> {
  op_ref: string;
  refund_ref: string | null;
  agent_code: string | null;
  mandate_id: string | null;
  /** bigint из pg — строкой. */
  amount: string;
  currency: string;
  at: string;
}

/** Точки в транзакции — только для тестов (гонка двух экземпляров). */
export interface PgRefundHooks {
  /** После BEGIN, до блокировки операции. */
  readonly beforeLock?: (op_ref: string) => Promise<void>;
  /** После вставки, до события и COMMIT. */
  readonly inserted?: (op_ref: string) => Promise<void>;
}

/**
 * На PostgreSQL (sql/117, sql/122; РП71 нюанс 2): транзакция — pg_advisory_xact_lock по op_ref (ожидание не дольше
 * lockTimeoutMs, превышение — исключение → 503), чтение возвратов операции, сверка (classifyRefund), вставка ON CONFLICT DO
 * NOTHING (второй барьер), событие — только если возвратов операции не было, COMMIT. Одновременные возвраты одной
 * операции — по одному: второй читает после фиксации первого.
 */
export class PgRefundStore implements RefundStore {
  private readonly lockTimeoutMs: number;
  private readonly hooks: PgRefundHooks;

  /** lockTimeoutMs — предел ожидания блокировки операции: adp_timeout_ms (РП71 нюанс 2, Р-1048). */
  constructor(
    private readonly client: TxSqlPool,
    opts: { readonly lockTimeoutMs: number; readonly hooks?: PgRefundHooks },
  ) {
    if (!Number.isSafeInteger(opts.lockTimeoutMs) || opts.lockTimeoutMs < 1) throw new Error("PgRefundStore: lockTimeoutMs — целое ≥ 1");
    this.lockTimeoutMs = opts.lockTimeoutMs;
    this.hooks = opts.hooks ?? {};
  }

  async record(r: RefundRecord, event: OperationEventDraft | undefined): Promise<RefundOutcome> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        await tx.query("SELECT set_config('lock_timeout', $1, true)", [`${this.lockTimeoutMs}ms`]);
        await this.hooks.beforeLock?.(r.op_ref);
        await tx.query("SELECT pg_advisory_xact_lock($1::bigint)", [refundLockKey(r.op_ref)]);
        // Чтение — после блокировки: снимок READ COMMITTED берётся на каждый оператор, видны все зафиксированные возвраты.
        const rows = await readRefunds(tx, r.op_ref);
        const decided = classifyRefund(rows, r);
        if (decided) {
          await tx.query("COMMIT");
          return decided;
        }
        // Второй барьер (нюанс 2): уникальный индекс (op_ref, refund_ref) NULLS NOT DISTINCT, sql/122.
        const ins = await tx.query(
          `INSERT INTO operation_refunds (${COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING RETURNING op_ref`,
          [r.op_ref, r.refund_ref, r.agent_code, r.mandate_id, r.amount, r.currency, r.at],
        );
        // Под блокировкой вставки не было, а записи ключа при чтении не было — не подтверждено, без догадки (инвариант 3).
        if (ins.rows.length !== 1) throw new Error("operation_refunds: конфликт вставки под блокировкой операции");
        await this.hooks.inserted?.(r.op_ref);
        if (event && rows.length === 0) await insertOperationEventTx(tx, event, r.at);
        await tx.query("COMMIT");
        return { kind: "inserted", all: [...rows, { ...r }] };
      } catch (err) {
        // Соединение, на котором не прошёл ROLLBACK, в пул не возвращается (как РП39).
        await tx.query("ROLLBACK").catch((rb: unknown) => {
          broken = rb instanceof Error ? rb : new Error(String(rb));
        });
        throw err;
      }
    } finally {
      tx.release(broken);
    }
  }

  async get(op_ref: string): Promise<RefundRecord | undefined> {
    return (await readRefunds(this.client, op_ref))[0];
  }

  async list(op_ref: string): Promise<RefundRecord[]> {
    return readRefunds(this.client, op_ref);
  }
}

/** Возвраты операции по времени записи (часы Платформы); при равенстве — без ссылки, затем по ссылке. */
async function readRefunds(client: SqlClient, op_ref: string): Promise<RefundRecord[]> {
  const res = await client.query<RefundRow>(`SELECT ${COLUMNS} FROM operation_refunds WHERE op_ref = $1 ORDER BY at, refund_ref NULLS FIRST`, [op_ref]);
  return res.rows.map((x) => ({
    op_ref: x.op_ref,
    refund_ref: x.refund_ref,
    agent_code: x.agent_code,
    mandate_id: x.mandate_id,
    amount: Number(x.amount),
    currency: x.currency,
    at: x.at,
  }));
}

export interface RefundDeps {
  readonly operations: OperationReader;
  readonly outcomes: Pick<OutcomeStore, "get">;
  readonly fulfilments: Pick<FulfilmentStore, "get">;
  readonly refunds: RefundStore;
  readonly reversals?: Pick<ReversalStore, "get">;
  readonly pushFor?: PushFor;
  readonly now?: () => Date;
  readonly log?: CollectorLog;
  readonly reorder_window_ms?: number;
}

const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
const CURRENCY = /^[A-Z]{3}$/;

/**
 * ПИ-3 REFUND (РП55 п. 3, РП71): после записи об исполнении — запись возврата и operation.refunded при первом возврате
 * операции; бюджет не меняется. Без клиринга — 503 (перестановка, п. 5); по операции без одобрения — 202 и инцидент;
 * после реверсала — по записи об исполнении, как без него (КТ1 п. 3); валюта ≠ операции — 400 и инцидент; refund_ref есть,
 * но не непустая строка — 400. Без refund_ref — один возврат на op_ref, с ним — на пару (op_ref, refund_ref); повтор —
 * 202; тот же ключ с другой суммой или валютой — 202 и инцидент, запись прежняя; смешение форм — 202 и инцидент без
 * записи (нюанс 1); сумма всех возвратов операции больше суммы клиринга — запись и инцидент (п. 4).
 */
export async function acceptRefund(deps: RefundDeps, msg: Readonly<Record<string, unknown>>): Promise<IssuerResponseStatus> {
  const log = deps.log ?? (() => {});
  const op_ref = msg.op_ref as string;
  const amount = msg.amount;
  const currency = msg.currency;
  const refund_ref = Object.hasOwn(msg, "refund_ref") ? msg.refund_ref : null;
  if (!isUnits(amount) || typeof currency !== "string" || !CURRENCY.test(currency)) return 400;
  // Есть, но не непустая строка (в том числе null) — не по форме (РП71 п. 1).
  if (Object.hasOwn(msg, "refund_ref") && (typeof refund_ref !== "string" || refund_ref === "")) return 400;
  const rec = await deps.operations.get(op_ref);
  if (!rec) return 202;
  if (rec.decision === null) return 503;
  if (rec.decision.decision !== "APPROVE") {
    log("warn", { op_ref, decision: rec.decision.decision, incident: true }, "П8: возврат по операции без APPROVE ADP");
    return 202;
  }
  const outcome = await deps.outcomes.get(op_ref);
  if (outcome && outcome.status !== "AUTHORIZED") {
    log("warn", { op_ref, status: outcome.status, incident: true }, "П8: возврат по операции без одобрения эмитента");
    return 202;
  }
  // Клиринг старше реверсала (РП55 «Дополнения КТ1» п. 3): есть запись об исполнении — возврат принимается и после
  // реверсала. Реверсал без клиринга — предшественник не придёт по этой авторизации: 503 и инцидент за окном, как без него.
  const f = await deps.fulfilments.get(op_ref);
  if (!f) {
    const missing = outcome || (await deps.reversals?.get(op_ref)) ? "PRESENTMENT" : "ISSUER_RESPONSE";
    return awaitPredecessor(deps, { op_ref, msg_type: "REFUND", decided_at: rec.at, missing });
  }
  if (currency !== f.currency) {
    log("warn", { op_ref, currency, expected: f.currency, incident: true }, "П8: валюта возврата не совпадает с валютой операции");
    return 400;
  }
  const r: RefundRecord = {
    op_ref,
    refund_ref: refund_ref as string | null,
    agent_code: f.agent_code,
    mandate_id: rec.mandate_id,
    amount,
    currency,
    at: (deps.now ?? (() => new Date()))().toISOString(),
  };
  // Сверка, вставка и событие (только у первого возврата операции) — атомарно в хранилище (РП71 п. 3, 5, нюанс 2).
  const res = await deps.refunds.record(r, await refundedEventFor(r, deps.pushFor));
  if (res.kind === "conflict") {
    const fields = { op_ref, refund_ref: r.refund_ref, prior: res.prior.amount, prior_currency: res.prior.currency, amount, currency, incident: true };
    log("warn", fields, "П8: возврат с тем же ключом и другой суммой или валютой — запись прежняя");
  } else if (res.kind === "mixed") {
    const fields = { op_ref, refund_ref: r.refund_ref, first_refund_ref: res.first.refund_ref, amount, incident: true };
    log("warn", fields, "П8: смешение форм возврата по операции — без записи (РП71 нюанс 1)");
  } else if (res.kind === "inserted") {
    // Сумма всех возвратов больше суммы клиринга — записывается как пришло (РП55 п. 3, РП71 п. 4): основание для спора (PS-22).
    const total = res.all.reduce((s, x) => s + x.amount, 0);
    if (total > f.final_amount) log("warn", { op_ref, refund_ref: r.refund_ref, amount, total, final_amount: f.final_amount, incident: true }, "П8: сумма возвратов больше суммы клиринга");
  }
  return 202;
}
