// П8 Реверсал и истечение авторизации (РП55 п. 1, PS-16 ч. 3): по ПИ-3 REVERSAL / AUTH_EXPIRED при APPROVE ADP без записи
// об исполнении — освобождение каждого удержания записи операции (РП11), затем запись (одна на op_ref, только вставка).
// События нет до ПАО 1.5.0 (п. 2): агент видит REVERSED по GET. В памяти (dev, стенд) и на PostgreSQL
// (sql/117_operation_reversals_refunds.sql). Номера карты и token_ref нет (инвариант 1).
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { OperationReader } from "../adp/operations.js";
import type { StateService } from "../state/index.js";
import type { CollectorLog, IssuerResponseStatus, OutcomeStore } from "./outcomes.js";
import type { FulfilmentStore } from "./records.js";

export type ReversalKind = "REVERSAL" | "AUTH_EXPIRED";
export const REVERSAL_KINDS: readonly string[] = ["REVERSAL", "AUTH_EXPIRED"];

export interface ReversalRecord {
  readonly op_ref: string;
  /** msg_type сообщения; агенту — reason при status REVERSED. */
  readonly kind: ReversalKind;
  /** Агент по домену токена из записи ADP; null — не установлен. */
  readonly agent_code: string | null;
  readonly mandate_id: string | null;
  readonly at: string;
}

/** Сбой любого метода — исключение. */
export interface ReversalStore {
  /** Атомарно: записи по op_ref нет — записать и вернуть undefined; есть — вернуть прежнюю, ничего не меняя. */
  record(r: ReversalRecord): Promise<ReversalRecord | undefined>;
  get(op_ref: string): Promise<ReversalRecord | undefined>;
}

export class MemoryReversalStore implements ReversalStore {
  readonly #rows = new Map<string, ReversalRecord>();

  async record(r: ReversalRecord): Promise<ReversalRecord | undefined> {
    const prior = this.#rows.get(r.op_ref);
    if (prior) return { ...prior };
    this.#rows.set(r.op_ref, Object.freeze({ ...r }));
    return undefined;
  }

  async get(op_ref: string): Promise<ReversalRecord | undefined> {
    const r = this.#rows.get(op_ref);
    return r && { ...r };
  }
}

const COLUMNS = "op_ref, kind, agent_code, mandate_id, at";

interface ReversalRow extends Record<string, unknown> {
  op_ref: string;
  kind: ReversalKind;
  agent_code: string | null;
  mandate_id: string | null;
  at: string;
}

/** На PostgreSQL (sql/117): вставка ON CONFLICT DO NOTHING; события нет — транзакция не нужна. */
export class PgReversalStore implements ReversalStore {
  constructor(private readonly client: SqlClient) {}

  async record(r: ReversalRecord): Promise<ReversalRecord | undefined> {
    const ins = await this.client.query(
      `INSERT INTO operation_reversals (${COLUMNS}) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (op_ref) DO NOTHING RETURNING op_ref`,
      [r.op_ref, r.kind, r.agent_code, r.mandate_id, r.at],
    );
    if (ins.rows.length === 1) return undefined;
    const prior = await this.get(r.op_ref);
    // Вставки не было, а строки нет — её быть не может (удаление запрещено): не подтверждено, без догадки.
    if (!prior) throw new Error("operation_reversals: запись не найдена после конфликта вставки");
    return prior;
  }

  async get(op_ref: string): Promise<ReversalRecord | undefined> {
    const res = await this.client.query<ReversalRow>(`SELECT ${COLUMNS} FROM operation_reversals WHERE op_ref = $1`, [op_ref]);
    const x = res.rows[0];
    return x && { op_ref: x.op_ref, kind: x.kind, agent_code: x.agent_code, mandate_id: x.mandate_id, at: x.at };
  }
}

export interface ReversalDeps {
  readonly operations: OperationReader;
  readonly outcomes: Pick<OutcomeStore, "get">;
  readonly fulfilments?: Pick<FulfilmentStore, "get">;
  readonly reversals: ReversalStore;
  readonly state: Pick<StateService, "release">;
  readonly now?: () => Date;
  readonly log?: CollectorLog;
}

const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;

/**
 * ПИ-3 REVERSAL / AUTH_EXPIRED (РП55 п. 1): по операции с APPROVE ADP без записи об исполнении — с итогом AUTHORIZED или до
 * ответа эмитента — освобождение каждого удержания записи операции, затем запись. Повтор освобождения безопасен
 * (RESERVATION_RELEASED — не сбой); сбой — 503 без записи. Частичного реверсала нет: amount ≠ одобренной — 400 и инцидент.
 * После клиринга — 202 и инцидент, закреплённое не трогается; решение не APPROVE или итог DECLINED — 202 без действий.
 */
export async function acceptReversal(deps: ReversalDeps, msg: Readonly<Record<string, unknown>>): Promise<IssuerResponseStatus> {
  const log = deps.log ?? (() => {});
  const op_ref = msg.op_ref as string;
  const kind = msg.msg_type as ReversalKind;
  const amount = msg.amount;
  if (amount !== undefined && amount !== null && !isUnits(amount)) return 400;
  const rec = await deps.operations.get(op_ref);
  if (!rec) return 202;
  if (rec.decision === null) return 503;
  if (rec.decision.decision !== "APPROVE") {
    log("info", { op_ref, kind, decision: rec.decision.decision }, "П8: реверсал по операции без APPROVE ADP — удержаний нет");
    return 202;
  }
  const outcome = await deps.outcomes.get(op_ref);
  if (outcome && outcome.status !== "AUTHORIZED") {
    log("info", { op_ref, kind, status: outcome.status }, "П8: реверсал по отклонённой операции — удержания уже освобождены");
    return 202;
  }
  if (await deps.fulfilments?.get(op_ref)) {
    log("warn", { op_ref, kind, incident: true }, "П8: реверсал после клиринга — закреплённое не трогается, путь — возврат");
    return 202;
  }
  if (await deps.reversals.get(op_ref)) return 202;
  if (typeof amount === "number") {
    // Одобренная сумма — из фактов записи ADP; у записей до sql/114 фактов нет — сверка невозможна, освобождение целиком.
    if (!rec.facts) log("warn", { op_ref, kind, amount }, "П8: сумма реверсала не сверена — фактов операции нет");
    else if (amount !== rec.facts.amount) {
      log("warn", { op_ref, kind, amount, authorized: rec.facts.amount, incident: true }, "П8: частичный реверсал не поддерживается — не освобождено");
      return 400;
    }
  }
  let committed = false;
  for (const hold_id of rec.holds) {
    const r = await deps.state.release(hold_id);
    if (r.ok) {
      if (r.hold.committed > 0) committed = true;
      continue;
    }
    if (r.code === "RESERVATION_RELEASED") continue;
    log("warn", { op_ref, hold_id, code: r.code }, "П8: удержание по реверсалу не освобождено — 503, процессинг повторит");
    return 503;
  }
  // Клиринг успел закрепить удержание между проверкой и освобождением (одновременные PRESENTMENT и REVERSAL): ядро
  // освободило только открытую часть, исполнение учтено — реверсал не записывается, инцидент.
  if (committed) {
    log("warn", { op_ref, kind, incident: true }, "П8: реверсал одновременно с клирингом — удержание закреплено, реверсал не записан");
    return 202;
  }
  await deps.reversals.record({
    op_ref,
    kind,
    agent_code: outcome?.agent_code ?? rec.facts?.agent_code ?? null,
    mandate_id: rec.mandate_id,
    at: (deps.now ?? (() => new Date()))().toISOString(),
  });
  return 202;
}
