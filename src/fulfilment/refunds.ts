// П8 Возврат (РП55 п. 3–4, PS-16 ч. 3): по ПИ-3 REFUND после записи об исполнении — запись (одна на op_ref, только
// вставка) и operation.refunded в одной транзакции. Бюджет мандата не восстанавливается (restore_budget_on_refund = false,
// РП9; true до PS-23 — отказ запуска): в П3 действий нет. В памяти (dev, стенд) и на PostgreSQL
// (sql/117_operation_reversals_refunds.sql). Номера карты и token_ref нет (инвариант 1).
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { OperationReader } from "../adp/operations.js";
import { insertOperationEventTx, type MemoryConsentStore, type TxSqlPool } from "../consent/store.js";
import type { OperationEventDraft } from "../pao/events.js";
import type { CollectorLog, IssuerResponseStatus, OutcomeStore, PushFor } from "./outcomes.js";
import { awaitPredecessor, type FulfilmentStore } from "./records.js";
import type { ReversalStore } from "./reversals.js";

export interface RefundRecord {
  readonly op_ref: string;
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

/** Сбой любого метода — исключение. */
export interface RefundStore {
  /** Атомарно: записи по op_ref нет — записать её и событие (если есть) и вернуть undefined; есть — вернуть прежнюю. */
  record(r: RefundRecord, event: OperationEventDraft | undefined): Promise<RefundRecord | undefined>;
  get(op_ref: string): Promise<RefundRecord | undefined>;
}

/** В памяти (dev, стенд): событие и запись — один синхронный шаг (событие первым, как запись об исполнении). */
export class MemoryRefundStore implements RefundStore {
  readonly #rows = new Map<string, RefundRecord>();

  constructor(private readonly events?: Pick<MemoryConsentStore, "appendOperationEventNow">) {}

  async record(r: RefundRecord, event: OperationEventDraft | undefined): Promise<RefundRecord | undefined> {
    const prior = this.#rows.get(r.op_ref);
    if (prior) return { ...prior };
    // Без await между событием и записью: сбой события оставляет операцию без записи — повтор ПИ-3 запишет.
    if (event) this.events?.appendOperationEventNow(event, r.at);
    this.#rows.set(r.op_ref, Object.freeze({ ...r }));
    return undefined;
  }

  async get(op_ref: string): Promise<RefundRecord | undefined> {
    const r = this.#rows.get(op_ref);
    return r && { ...r };
  }
}

const COLUMNS = "op_ref, agent_code, mandate_id, amount, currency, at";

interface RefundRow extends Record<string, unknown> {
  op_ref: string;
  agent_code: string | null;
  mandate_id: string | null;
  /** bigint из pg — строкой. */
  amount: string;
  currency: string;
  at: string;
}

/**
 * На PostgreSQL (sql/117): транзакция — вставка ON CONFLICT DO NOTHING, при вставке — событие под блокировкой агента,
 * COMMIT. Из одновременных записей одного op_ref вставляет одна: вторая ждёт фиксации первой и читает прежнюю запись.
 */
export class PgRefundStore implements RefundStore {
  constructor(
    private readonly client: TxSqlPool,
    /** Точка в транзакции после вставки, до события и COMMIT — только для тестов (гонка двух экземпляров). */
    private readonly hooks: { readonly inserted?: (op_ref: string) => Promise<void> } = {},
  ) {}

  async record(r: RefundRecord, event: OperationEventDraft | undefined): Promise<RefundRecord | undefined> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        const ins = await tx.query(
          `INSERT INTO operation_refunds (${COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (op_ref) DO NOTHING RETURNING op_ref`,
          [r.op_ref, r.agent_code, r.mandate_id, r.amount, r.currency, r.at],
        );
        let prior: RefundRecord | undefined;
        if (ins.rows.length === 1) {
          await this.hooks.inserted?.(r.op_ref);
          if (event) await insertOperationEventTx(tx, event, r.at);
        } else {
          prior = await readRefund(tx, r.op_ref);
          // Вставки не было, а строки нет — её быть не может (удаление запрещено): не подтверждено, без догадки.
          if (!prior) throw new Error("operation_refunds: запись не найдена после конфликта вставки");
        }
        await tx.query("COMMIT");
        return prior;
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
    return readRefund(this.client, op_ref);
  }
}

async function readRefund(client: SqlClient, op_ref: string): Promise<RefundRecord | undefined> {
  const res = await client.query<RefundRow>(`SELECT ${COLUMNS} FROM operation_refunds WHERE op_ref = $1`, [op_ref]);
  const x = res.rows[0];
  return x && { op_ref: x.op_ref, agent_code: x.agent_code, mandate_id: x.mandate_id, amount: Number(x.amount), currency: x.currency, at: x.at };
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
 * ПИ-3 REFUND (РП55 п. 3): после записи об исполнении — запись возврата и operation.refunded; бюджет не меняется. Без
 * клиринга — 503 (перестановка, п. 5); по операции без одобрения — 202 и инцидент; после реверсала — по записи об
 * исполнении, как без него (КТ1 п. 3); валюта ≠ операции —
 * 400 и инцидент; больше суммы клиринга — запись и инцидент; второй возврат с другой суммой — 202 и инцидент.
 */
export async function acceptRefund(deps: RefundDeps, msg: Readonly<Record<string, unknown>>): Promise<IssuerResponseStatus> {
  const log = deps.log ?? (() => {});
  const op_ref = msg.op_ref as string;
  const amount = msg.amount;
  const currency = msg.currency;
  if (!isUnits(amount) || typeof currency !== "string" || !CURRENCY.test(currency)) return 400;
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
  const prior = await deps.refunds.get(op_ref);
  if (prior) {
    if (prior.amount !== amount) log("warn", { op_ref, prior: prior.amount, amount, incident: true }, "П8: второй возврат с другой суммой — запись прежняя (несколько возвратов — PS-23)");
    return 202;
  }
  // Больше суммы клиринга — записывается как пришло (решение владельца, РП55 п. 3): основание для спора (PS-22).
  if (amount > f.final_amount) log("warn", { op_ref, amount, final_amount: f.final_amount, incident: true }, "П8: возврат больше суммы клиринга");
  const r: RefundRecord = {
    op_ref,
    agent_code: f.agent_code,
    mandate_id: rec.mandate_id,
    amount,
    currency,
    at: (deps.now ?? (() => new Date()))().toISOString(),
  };
  const raced = await deps.refunds.record(r, await refundedEventFor(r, deps.pushFor));
  if (raced && raced.amount !== amount) log("warn", { op_ref, prior: raced.amount, amount, incident: true }, "П8: одновременный возврат с другой суммой — запись прежняя");
  return 202;
}
