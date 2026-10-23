// П8 Запись об исполнении (РП53, PS-16 ч. 2): по ПИ-3 PRESENTMENT — закрепление удержаний записи операции, запись
// (одна на op_ref, только вставка) и событие operation.settled в одной транзакции. Формирует Платформа по сообщению
// процессинга, не агент (A1 п. 6.2, инвариант 5). В памяти (dev, стенд) и на PostgreSQL (sql/115_fulfilments.sql).
// Номера карты и token_ref нет (инвариант 1).
import { createHash } from "node:crypto";
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { OperationReader } from "../adp/operations.js";
import { insertOperationEventTx, type MemoryConsentStore, type TxSqlPool } from "../consent/store.js";
import type { OperationEventDraft } from "../pao/events.js";
import type { StateService } from "../state/index.js";
import { acceptIssuerResponse, type CollectorLog, type IssuerResponseDeps, type IssuerResponseStatus, type OutcomeStore, type PushFor } from "./outcomes.js";

/** Сопоставление с пределами (РП53 п. 5, 6, 8); перечень — текстом AGENT-PROTOCOL §5, enum — ПАО 1.5.0 (#37). */
export type ScopeCheck = "WITHIN_LIMITS" | "EXCEEDS_AUTHORIZATION" | "NOT_RESERVED";

export interface FulfilmentRecord {
  readonly op_ref: string;
  readonly fulfilment_ref: string;
  /** Агент по домену токена; null — не установлен: запись есть, события нет (РП53 п. 9). */
  readonly agent_code: string | null;
  readonly mandate_id: string | null;
  readonly order_ref: string | null;
  readonly merchant_id: string | null;
  /** Одобренная сумма — из записи операции ADP (сообщение процессинга ПИ-1). */
  readonly authorized_amount: number;
  /** Сумма представления — из сообщения процессинга ПИ-3. */
  readonly final_amount: number;
  readonly currency: string;
  readonly scope_check: ScopeCheck;
  /** Закреплено по мандату записи операции после закрепления (накопленное по CART, A1 п. 6.3). */
  readonly spent_position: number;
  readonly at: string;
}

export const FULFILMENT_REF_DOMAIN = "pao:fulfilment-ref:v1";

/** fulfilment_ref (РП53 п. 8): детерминированно от op_ref — повтор даёт ту же ссылку; 28 символов — под aoi.fulfilment_ref. */
export function fulfilmentRefFor(op_ref: string): string {
  return `ful_${createHash("sha256").update(`${FULFILMENT_REF_DOMAIN}\n${op_ref}`).digest("hex").slice(0, 24)}`;
}

/** operation.settled — только агенту из домена токена; data — только {op_ref} (РП53 п. 9, A7 п. 8.3). */
export function settledEventFor(f: FulfilmentRecord, pushFor?: PushFor): OperationEventDraft | undefined {
  if (f.agent_code === null) return undefined;
  return { agent_code: f.agent_code, type: "operation.settled", data: { op_ref: f.op_ref }, push: pushFor?.(f.agent_code, "operation.settled") ?? false };
}

/** Сбой любого метода — исключение. */
export interface FulfilmentStore {
  /** Атомарно: записи по op_ref нет — записать её и событие (если есть) и вернуть undefined; есть — вернуть прежнюю. */
  record(f: FulfilmentRecord, event: OperationEventDraft | undefined): Promise<FulfilmentRecord | undefined>;
  get(op_ref: string): Promise<FulfilmentRecord | undefined>;
}

/** В памяти (dev, стенд): событие и запись — один синхронный шаг (событие первым, как итог РП52). */
export class MemoryFulfilmentStore implements FulfilmentStore {
  readonly #rows = new Map<string, FulfilmentRecord>();

  constructor(private readonly events?: Pick<MemoryConsentStore, "appendOperationEventNow">) {}

  async record(f: FulfilmentRecord, event: OperationEventDraft | undefined): Promise<FulfilmentRecord | undefined> {
    const prior = this.#rows.get(f.op_ref);
    if (prior) return { ...prior };
    // Без await между событием и записью: сбой события оставляет операцию без записи — повтор ПИ-3 запишет.
    if (event) this.events?.appendOperationEventNow(event, f.at);
    this.#rows.set(f.op_ref, Object.freeze({ ...f }));
    return undefined;
  }

  async get(op_ref: string): Promise<FulfilmentRecord | undefined> {
    const r = this.#rows.get(op_ref);
    return r && { ...r };
  }
}

const COLUMNS =
  "op_ref, fulfilment_ref, agent_code, mandate_id, order_ref, merchant_id, authorized_amount, final_amount, currency, scope_check, spent_position, at";

interface FulfilmentRow extends Record<string, unknown> {
  op_ref: string;
  fulfilment_ref: string;
  agent_code: string | null;
  mandate_id: string | null;
  order_ref: string | null;
  merchant_id: string | null;
  /** bigint из pg — строкой. */
  authorized_amount: string;
  final_amount: string;
  currency: string;
  scope_check: ScopeCheck;
  spent_position: string;
  at: string;
}

/**
 * На PostgreSQL (sql/115): транзакция — вставка ON CONFLICT DO NOTHING, при вставке — событие под блокировкой агента,
 * COMMIT. Из одновременных записей одного op_ref вставляет одна: вторая ждёт фиксации первой и читает прежнюю запись.
 */
export class PgFulfilmentStore implements FulfilmentStore {
  constructor(
    private readonly client: TxSqlPool,
    /** Точка в транзакции после вставки, до события и COMMIT — только для тестов (гонка двух экземпляров). */
    private readonly hooks: { readonly inserted?: (op_ref: string) => Promise<void> } = {},
  ) {}

  async record(f: FulfilmentRecord, event: OperationEventDraft | undefined): Promise<FulfilmentRecord | undefined> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        const ins = await tx.query(
          `INSERT INTO fulfilments (${COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           ON CONFLICT (op_ref) DO NOTHING RETURNING op_ref`,
          [f.op_ref, f.fulfilment_ref, f.agent_code, f.mandate_id, f.order_ref, f.merchant_id, f.authorized_amount, f.final_amount, f.currency, f.scope_check, f.spent_position, f.at],
        );
        let prior: FulfilmentRecord | undefined;
        if (ins.rows.length === 1) {
          await this.hooks.inserted?.(f.op_ref);
          if (event) await insertOperationEventTx(tx, event, f.at);
        } else {
          prior = await readFulfilment(tx, f.op_ref);
          // Вставки не было, а строки нет — её быть не может (удаление запрещено): не подтверждено, без догадки.
          if (!prior) throw new Error("fulfilments: запись не найдена после конфликта вставки");
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

  async get(op_ref: string): Promise<FulfilmentRecord | undefined> {
    return readFulfilment(this.client, op_ref);
  }
}

async function readFulfilment(client: SqlClient, op_ref: string): Promise<FulfilmentRecord | undefined> {
  const r = await client.query<FulfilmentRow>(`SELECT ${COLUMNS} FROM fulfilments WHERE op_ref = $1`, [op_ref]);
  const x = r.rows[0];
  return (
    x && {
      op_ref: x.op_ref,
      fulfilment_ref: x.fulfilment_ref,
      agent_code: x.agent_code,
      mandate_id: x.mandate_id,
      order_ref: x.order_ref,
      merchant_id: x.merchant_id,
      authorized_amount: Number(x.authorized_amount),
      final_amount: Number(x.final_amount),
      currency: x.currency,
      scope_check: x.scope_check,
      spent_position: Number(x.spent_position),
      at: x.at,
    }
  );
}

/** ПИ-3 целиком: ответ эмитента (РП52) и клиринг (РП53); без fulfilments PRESENTMENT — 503, как до ч. 2. */
export interface OperationEventDeps extends IssuerResponseDeps {
  readonly state: Pick<StateService, "release" | "hold" | "commit" | "committed">;
  readonly outcomes?: Pick<OutcomeStore, "get">;
  readonly fulfilments?: FulfilmentStore;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
const CURRENCY = /^[A-Z]{3}$/;

/**
 * ПИ-3 POST /adp/v1/events: ISSUER_RESPONSE — РП52 (acceptIssuerResponse), PRESENTMENT — РП53 (acceptPresentment);
 * прочие типы — 503 до PS-16 ч. 3 (процессинг повторит). Снимок входа до первого await (Р-205).
 */
export async function acceptOperationEvent(deps: OperationEventDeps, raw: unknown): Promise<IssuerResponseStatus> {
  if (!isObj(raw)) return 400;
  const msg = structuredClone(raw);
  if (typeof msg.op_ref !== "string" || msg.op_ref === "" || typeof msg.msg_type !== "string") return 400;
  if (msg.msg_type === "PRESENTMENT" && deps.fulfilments) return acceptPresentment({ ...deps, fulfilments: deps.fulfilments, outcomes: deps.outcomes ?? deps.store }, msg);
  return acceptIssuerResponse(deps, msg);
}

export interface PresentmentDeps {
  readonly operations: OperationReader;
  readonly outcomes: Pick<OutcomeStore, "get">;
  readonly fulfilments: FulfilmentStore;
  readonly state: Pick<StateService, "hold" | "commit" | "committed">;
  readonly pushFor?: PushFor;
  readonly now?: () => Date;
  readonly log?: CollectorLog;
}

/**
 * ПИ-3 PRESENTMENT (РП53 п. 2–9): по операции с итогом AUTHORIZED — закрепление каждого удержания записи операции суммой
 * представления, не больше удержанной (остаток освобождает ядро), запись об исполнении и operation.settled. APPROVE без
 * ответа эмитента — 503 (процессинг повторит); иной итог — 202 и инцидент; валюта ≠ операции — 400 и инцидент; сбой — 503.
 */
export async function acceptPresentment(deps: PresentmentDeps, msg: Readonly<Record<string, unknown>>): Promise<IssuerResponseStatus> {
  const log = deps.log ?? (() => {});
  const op_ref = msg.op_ref as string;
  const amount = msg.amount;
  const currency = msg.currency;
  if (!isUnits(amount) || typeof currency !== "string" || !CURRENCY.test(currency)) return 400;
  const rec = await deps.operations.get(op_ref);
  if (!rec) return 202;
  if (rec.decision === null) return 503;
  if (rec.decision.decision !== "APPROVE") {
    log("warn", { op_ref, decision: rec.decision.decision, incident: true }, "П8: представление по операции без APPROVE ADP");
    return 202;
  }
  const outcome = await deps.outcomes.get(op_ref);
  if (!outcome) {
    log("info", { op_ref }, "П8: представление раньше ответа эмитента — 503, процессинг повторит");
    return 503;
  }
  if (outcome.status !== "AUTHORIZED") {
    log("warn", { op_ref, status: outcome.status, incident: true }, "П8: представление по операции без одобрения эмитента");
    return 202;
  }
  // Одобренная сумма и валюта — из записи операции (сообщение ПИ-1); у записей до sql/114 фактов нет — из удержания.
  let authorized = rec.facts ? { amount: rec.facts.amount, currency: rec.facts.currency } : undefined;
  if (!authorized && rec.holds[0] !== undefined) {
    const h = await deps.state.hold(rec.holds[0]);
    if (h.ok) authorized = { amount: h.hold.amount, currency: h.hold.currency };
    else if (h.code !== "RESERVATION_RELEASED") return 503;
  }
  if (!authorized) {
    // Запись до sql/114 без фактов и с освобождённым удержанием: сумму и валюту операции не установить — 202 и инцидент,
    // а не бесконечный 503 (ревью КТ1 № 4).
    log("warn", { op_ref, incident: true }, "П8: одобренная сумма операции не установлена — представление не принято");
    return 202;
  }
  if (currency !== authorized.currency) {
    log("warn", { op_ref, currency, expected: authorized.currency, incident: true }, "П8: валюта представления не совпадает с валютой операции");
    return 400;
  }
  const prior = await deps.fulfilments.get(op_ref);
  if (prior) {
    if (prior.final_amount !== amount) log("warn", { op_ref, prior: prior.final_amount, amount, incident: true }, "П8: второе представление с другой суммой — запись прежняя");
    return 202;
  }
  // Закрепление по удержаниям в порядке резерва (РП53 п. 2): повтор распознаёт П3. Освобождённое — NOT_RESERVED, открытые
  // закрепляются (п. 6, решение владельца на КТ1 № 3: бюджет — в безопасную сторону).
  let notReserved = rec.holds.length === 0;
  /** Удержания, закреплённые прежде другой суммой (сбой между закреплением и записью, КТ1 № 1): сумма из П3. */
  const conflicts: { hold_id: string; committed: number }[] = [];
  for (const hold_id of rec.holds) {
    const h = await deps.state.hold(hold_id);
    if (!h.ok) {
      if (h.code !== "RESERVATION_RELEASED") return 503;
      notReserved = true;
      continue;
    }
    const r = await deps.state.commit(hold_id, { amount: Math.min(amount, h.hold.amount), currency: h.hold.currency });
    if (r.ok) continue;
    if (r.code === "RESERVATION_RELEASED") {
      notReserved = true;
    } else if (r.code === "COMMIT_CONFLICT") {
      const read = await deps.state.hold(hold_id);
      if (!read.ok) return 503;
      conflicts.push({ hold_id, committed: read.hold.committed });
    } else {
      log("warn", { op_ref, hold_id, code: r.code }, "П8: удержание не закреплено — 503, процессинг повторит");
      return 503;
    }
  }
  // Записи нет, а удержание закреплено другой суммой: запись — по сумме повтора, в инциденте — обе суммы (КТ1 № 1).
  if (conflicts.length > 0) log("warn", { op_ref, amount, committed: conflicts, incident: true }, "П8: удержания закреплены другой суммой — запись по сумме представления");
  const spent = rec.mandate_id === null ? 0 : await deps.state.committed(rec.mandate_id);
  if (spent === undefined) return 503;
  const scope_check: ScopeCheck = notReserved ? "NOT_RESERVED" : amount > authorized.amount ? "EXCEEDS_AUTHORIZATION" : "WITHIN_LIMITS";
  if (scope_check !== "WITHIN_LIMITS") log("warn", { op_ref, scope_check, amount, authorized: authorized.amount, incident: true }, "П8: клиринг вне одобренного резерва");
  const f: FulfilmentRecord = {
    op_ref,
    fulfilment_ref: fulfilmentRefFor(op_ref),
    agent_code: outcome.agent_code,
    mandate_id: rec.mandate_id,
    order_ref: rec.facts?.order_ref ?? null,
    merchant_id: rec.facts?.merchant_id ?? null,
    authorized_amount: authorized.amount,
    final_amount: amount,
    currency,
    scope_check,
    spent_position: spent,
    at: (deps.now ?? (() => new Date()))().toISOString(),
  };
  const raced = await deps.fulfilments.record(f, settledEventFor(f, deps.pushFor));
  if (raced && raced.final_amount !== amount) log("warn", { op_ref, prior: raced.final_amount, amount, incident: true }, "П8: одновременное представление с другой суммой — запись прежняя");
  return 202;
}
