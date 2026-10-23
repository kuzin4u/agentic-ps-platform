// П8 Итог операции (РП52, PS-16 ч. 1): один итог на op_ref, только вставка; итог с установленным агентом — событие
// operation.* в той же транзакции (третий источник ленты, п. 7). Источники: сборщик по решённым отказам ADP вне пути
// авторизации (п. 1 (а), как уведомитель РП46 доп. п. 7) и ответ эмитента по ПИ-3 (п. 1 (б), К1.2). В памяти (dev,
// стенд) и на PostgreSQL (sql/114_operation_outcomes.sql). Номера карты и token_ref нет (инвариант 1).
import type { SqlClient } from "@kuzin4u/agentic-core";
import type { OperationReader, OperationRecord } from "../adp/operations.js";
import type { StateService } from "../state/index.js";
import { insertOperationEventTx, type MemoryConsentStore, type TxSqlPool } from "../consent/store.js";
import type { OperationEventDraft, PaoEventType } from "../pao/events.js";
import type { Decision } from "../shared/canonical.generated.js";

export type OutcomeStatus = "AUTHORIZED" | "DECLINED" | "CONFIRMATION_REQUIRED";
export type OutcomeSource = "ADP" | "ISSUER";

export interface OperationOutcome {
  readonly op_ref: string;
  /** Агент по домену токена; null — не установлен (РП52 п. 5): итог есть, события нет. */
  readonly agent_code: string | null;
  readonly status: OutcomeStatus;
  /** Код отказа ADP, ISSUER_DECLINED или CONFIRMATION_REQUIRED; у AUTHORIZED — null. */
  readonly reason: string | null;
  readonly source: OutcomeSource;
  readonly at: string;
}

/** Причина отказа эмитента (РП52 п. 6 (а)): кода причины в канонической модели нет — issuer_reason к ПАО 1.5.0 (#37). */
export const ISSUER_DECLINED = "ISSUER_DECLINED";

/** Закрытый перечень причин operation.declined (РП52 п. 6): другой причины событие не несёт. */
export const DECLINE_EVENT_REASONS = [
  "AOI_MISMATCH",
  "AGENT_SUSPENDED",
  "CREDENTIAL_INVALID",
  "MANDATE_NOT_FOUND",
  "MANDATE_EXPIRED",
  "MANDATE_REVOKED",
  "MANDATE_SCOPE",
  "LIMIT_EXCEEDED",
  "STATE_UNAVAILABLE",
  ISSUER_DECLINED,
] as const;

const eventReason = (r: string | null): boolean => r !== null && (DECLINE_EVENT_REASONS as readonly string[]).includes(r);

/** Решённая запись операции без итога — работа сборщика. */
export interface DecidedOp {
  readonly op_ref: string;
  readonly decision: Decision;
  readonly agent_code: string | null;
  readonly at: string;
}

/** Итог по решению ADP (п. 3): DECLINE → DECLINED с кодом, CONFIRMATION_REQUIRED — без события; APPROVE ждёт эмитента. */
export function outcomeFromDecision(op: DecidedOp, at: string): OperationOutcome | undefined {
  const d = op.decision;
  if (d.decision === "DECLINE") {
    return { op_ref: op.op_ref, agent_code: op.agent_code, status: "DECLINED", reason: d.reason ?? null, source: "ADP", at };
  }
  if (d.decision === "CONFIRMATION_REQUIRED") {
    return { op_ref: op.op_ref, agent_code: op.agent_code, status: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED", source: "ADP", at };
  }
  return undefined;
}

/** Строка попытки push в транзакции события (РП40 п. 5): агент ACTIVE и подписан на тип — на момент записи. */
export type PushFor = (agent_code: string, type: PaoEventType) => boolean;

/**
 * Событие итога (п. 2–7): только агенту, установленному по домену токена; AUTHORIZED — operation.authorized, DECLINED с
 * причиной из перечня — operation.declined; CONFIRMATION_REQUIRED и прочее — без события. data — только {op_ref}.
 */
export function eventFor(o: OperationOutcome, pushFor?: PushFor): OperationEventDraft | undefined {
  if (o.agent_code === null) return undefined;
  const type = o.status === "AUTHORIZED" ? "operation.authorized" : o.status === "DECLINED" && eventReason(o.reason) ? "operation.declined" : undefined;
  if (type === undefined) return undefined;
  return { agent_code: o.agent_code, type, data: { op_ref: o.op_ref }, push: pushFor?.(o.agent_code, type) ?? false };
}

/** Сбой любого метода — исключение. */
export interface OutcomeStore {
  /** Решённые записи DECLINE и CONFIRMATION_REQUIRED без итога, с at ≥ sinceAt, по возрастанию at. */
  pending(sinceAt: string, limit: number): Promise<readonly DecidedOp[]>;
  /** Самая старая такая запись с at ≥ sinceAt — признак отставания (РП52 «Дополнения» п. 2). */
  oldestPending(sinceAt: string): Promise<string | undefined>;
  /**
   * Атомарно: итога по op_ref нет — записать итог и событие (если есть) одной транзакцией и вернуть undefined; есть —
   * вернуть прежний, ничего не меняя (п. 8).
   */
  record(o: OperationOutcome, event: OperationEventDraft | undefined): Promise<OperationOutcome | undefined>;
  get(op_ref: string): Promise<OperationOutcome | undefined>;
}

const fromRecord = (r: OperationRecord): DecidedOp | undefined =>
  r.decision && (r.decision.decision === "DECLINE" || r.decision.decision === "CONFIRMATION_REQUIRED")
    ? { op_ref: r.op_ref, decision: r.decision, agent_code: r.facts?.agent_code ?? r.notify?.agent_code ?? null, at: r.at }
    : undefined;

/** Записи операций в памяти (MemoryOperationStore.records). */
export interface OperationRecords {
  records(): Iterable<OperationRecord>;
}

/** В памяти (dev, стенд): один процесс — одна очередь; итог и событие — один синхронный шаг (событие первым, как РП51). */
export class MemoryOutcomeStore implements OutcomeStore {
  readonly #rows = new Map<string, OperationOutcome>();

  constructor(
    private readonly operations: OperationRecords,
    /** Лента агента в памяти; без неё (тесты П8 без ленты) события не пишутся. */
    private readonly events?: Pick<MemoryConsentStore, "appendOperationEventNow">,
  ) {}

  async pending(sinceAt: string, limit: number): Promise<readonly DecidedOp[]> {
    const out: DecidedOp[] = [];
    for (const r of this.operations.records()) {
      const op = fromRecord(r);
      if (op && op.at >= sinceAt && !this.#rows.has(op.op_ref)) out.push(op);
    }
    return out.sort((a, b) => (a.at === b.at ? (a.op_ref < b.op_ref ? -1 : 1) : a.at < b.at ? -1 : 1)).slice(0, limit);
  }

  async oldestPending(sinceAt: string): Promise<string | undefined> {
    return (await this.pending(sinceAt, 1))[0]?.at;
  }

  async record(o: OperationOutcome, event: OperationEventDraft | undefined): Promise<OperationOutcome | undefined> {
    const prior = this.#rows.get(o.op_ref);
    if (prior) return { ...prior };
    // Без await между событием и итогом: сбой события оставляет операцию без итога — её возьмёт следующий проход.
    if (event) this.events?.appendOperationEventNow(event, o.at);
    this.#rows.set(o.op_ref, Object.freeze({ ...o }));
    return undefined;
  }

  async get(op_ref: string): Promise<OperationOutcome | undefined> {
    const r = this.#rows.get(op_ref);
    return r && { ...r };
  }
}

interface OutcomeRow extends Record<string, unknown> {
  op_ref: string;
  agent_code: string | null;
  status: OutcomeStatus;
  reason: string | null;
  source: OutcomeSource;
  at: string;
}

/** Та же выборка в pending и oldestPending; NOT EXISTS — по первичному ключу итогов. */
const PENDING_WHERE = `o.decision IS NOT NULL AND o.decision->>'decision' IN ('DECLINE', 'CONFIRMATION_REQUIRED') AND o.at >= $1
     AND NOT EXISTS (SELECT 1 FROM operation_outcomes x WHERE x.op_ref = o.op_ref)`;

/**
 * На PostgreSQL (sql/114): транзакция — вставка итога ON CONFLICT DO NOTHING, при вставке — событие под блокировкой агента
 * (insertOperationEventTx), COMMIT. Из одновременных записей одного op_ref (два экземпляра сборщика, повтор ПИ-3) вставляет
 * одна: вторая ждёт фиксации первой на уникальном ключе и читает прежний итог — второго события нет.
 */
export class PgOutcomeStore implements OutcomeStore {
  constructor(
    private readonly client: TxSqlPool,
    /** Точка в транзакции после вставки итога, до события и COMMIT — только для тестов (гонка двух экземпляров). */
    private readonly hooks: { readonly inserted?: (op_ref: string) => Promise<void> } = {},
  ) {}

  async pending(sinceAt: string, limit: number): Promise<readonly DecidedOp[]> {
    const r = await this.client.query<{ op_ref: string; decision: Decision; agent_code: string | null; at: string }>(
      `SELECT o.op_ref, o.decision, o.agent_code, o.at FROM adp_operations o WHERE ${PENDING_WHERE} ORDER BY o.at, o.op_ref LIMIT $2`,
      [sinceAt, limit],
    );
    return r.rows.map((x) => ({ op_ref: x.op_ref, decision: x.decision, agent_code: x.agent_code, at: x.at }));
  }

  async oldestPending(sinceAt: string): Promise<string | undefined> {
    const r = await this.client.query<{ at: string | null }>(`SELECT min(o.at) AS at FROM adp_operations o WHERE ${PENDING_WHERE}`, [sinceAt]);
    return r.rows[0]?.at ?? undefined;
  }

  async record(o: OperationOutcome, event: OperationEventDraft | undefined): Promise<OperationOutcome | undefined> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        const ins = await tx.query(
          `INSERT INTO operation_outcomes (op_ref, agent_code, status, reason, source, at) VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (op_ref) DO NOTHING RETURNING op_ref`,
          [o.op_ref, o.agent_code, o.status, o.reason, o.source, o.at],
        );
        let prior: OperationOutcome | undefined;
        if (ins.rows.length === 1) {
          await this.hooks.inserted?.(o.op_ref);
          if (event) await insertOperationEventTx(tx, event, o.at);
        } else {
          prior = await readOutcome(tx, o.op_ref);
          // Вставки не было, а строки нет — её быть не может (удаление запрещено): не подтверждено, без догадки.
          if (!prior) throw new Error("operation_outcomes: итог не найден после конфликта вставки");
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

  async get(op_ref: string): Promise<OperationOutcome | undefined> {
    return readOutcome(this.client, op_ref);
  }
}

async function readOutcome(client: SqlClient, op_ref: string): Promise<OperationOutcome | undefined> {
  const r = await client.query<OutcomeRow>("SELECT op_ref, agent_code, status, reason, source, at FROM operation_outcomes WHERE op_ref = $1", [op_ref]);
  const x = r.rows[0];
  return x && { op_ref: x.op_ref, agent_code: x.agent_code, status: x.status, reason: x.reason, source: x.source, at: x.at };
}

/** Ответ ПИ-3: 202 — принято (в том числе без действий), 400 — сообщение не по форме, 503 — не обработано, повторить. */
export type IssuerResponseStatus = 202 | 400 | 503;

export interface IssuerResponseDeps {
  readonly operations: OperationReader;
  readonly store: OutcomeStore;
  /** hold — проверка удержаний при одобрении эмитента (РП53 п. 11); без него проверки нет. */
  readonly state: Pick<StateService, "release"> & Partial<Pick<StateService, "hold">>;
  readonly pushFor?: PushFor;
  readonly now?: () => Date;
  readonly log?: CollectorLog;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * ПИ-3 `ISSUER_RESPONSE` (РП52 п. 1 (б), 2, 3 (б), 8): по операции с APPROVE ADP — итог AUTHORIZED или DECLINED /
 * ISSUER_DECLINED и событие в одной транзакции; при отказе — освобождение удержаний записи операции. op_ref без записи ADP
 * (BYPASS, неагентская) — 202 без действий (инвариант 2); запись «в работе» — 503. Повтор — прежний итог без второго
 * события (идемпотентность по op_ref покрывает (op_ref, msg_type, seq)); иной второй итог — инцидент, итог прежний.
 */
export async function acceptIssuerResponse(deps: IssuerResponseDeps, raw: unknown): Promise<IssuerResponseStatus> {
  const log = deps.log ?? (() => {});
  // Снимок входа вызывающего до первого await (Р-205): разбор и итог — из одного сообщения.
  if (!isObj(raw)) return 400;
  const msg = structuredClone(raw);
  const op_ref = msg.op_ref;
  if (typeof op_ref !== "string" || op_ref === "") return 400;
  if (msg.msg_type !== "ISSUER_RESPONSE") {
    // Прочие типы ПИ-3 — PS-16 ч. 2 (РП52 п. 13): 503, а не 202 — процессинг повторит, событие не теряется молча
    // (PRESENTMENT без закрепления вернул бы бюджет по reservation_ttl — инвариант 4).
    if (typeof msg.msg_type !== "string") return 400;
    log("warn", { op_ref, msg_type: msg.msg_type }, "П8: тип события ПИ-3 ещё не обрабатывается — 503");
    return 503;
  }
  if (typeof msg.issuer_approved !== "boolean") return 400;
  const approved = msg.issuer_approved;
  const rec = await deps.operations.get(op_ref);
  if (!rec) return 202;
  if (rec.decision === null) return 503;
  if (rec.decision.decision !== "APPROVE") {
    log("warn", { op_ref, decision: rec.decision.decision, issuer_approved: approved, incident: true }, "П8: ответ эмитента по операции без APPROVE ADP");
    return 202;
  }
  const o: OperationOutcome = {
    op_ref,
    agent_code: rec.facts?.agent_code ?? null,
    status: approved ? "AUTHORIZED" : "DECLINED",
    reason: approved ? null : ISSUER_DECLINED,
    source: "ISSUER",
    at: (deps.now ?? (() => new Date()))().toISOString(),
  };
  const prior = await deps.store.record(o, eventFor(o, deps.pushFor));
  if (prior && (prior.status !== o.status || prior.reason !== o.reason)) {
    log("warn", { op_ref, prior: prior.status, issuer_approved: approved, incident: true }, "П8: второй ответ эмитента с иным исходом — итог прежний");
    return 202;
  }
  // Одобрение после освобождения удержания (РП53 п. 11, РП52 остаточный риск 5): итог уже записан — эмитент одобрил;
  // освобождённое — инцидент, нового резерва нет (РП41 п. 6). Проверка диагностическая: сбой чтения — предупреждение.
  if (approved && !prior && deps.state.hold) {
    for (const hold_id of rec.holds) {
      const h = await deps.state.hold(hold_id);
      if (h.ok) continue;
      if (h.code === "RESERVATION_RELEASED") log("warn", { op_ref, hold_id, incident: true }, "П8: одобрение эмитента по освобождённому удержанию — бюджет не держит операцию");
      else log("warn", { op_ref, hold_id, code: h.code }, "П8: удержание при одобрении эмитента не проверено");
    }
  }
  // Освобождение — и при повторе того же отказа: прошлый вызов мог записать итог и не освободить (повтор release безопасен).
  // Сбой — 503 (РП52 п. 3, решение владельца на КТ1): процессинг повторит, итог уже записан, второго события нет.
  if (!approved) {
    let failed = false;
    for (const hold_id of rec.holds) {
      const r = await deps.state.release(hold_id);
      if (!r.ok && r.code !== "RESERVATION_RELEASED") {
        failed = true;
        log("warn", { op_ref, hold_id, code: r.code }, "П8: удержание по отказу эмитента не освобождено — 503, процессинг повторит");
      }
    }
    if (failed) return 503;
  }
  return 202;
}

/** Сколько записей сборщик разбирает за проход. */
export const OUTCOME_BATCH = 100;

export type CollectorLog = (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;

export interface CollectorResult {
  readonly recorded: number;
  readonly failed: number;
  /** Неразобранная запись старше operation_outcome_max_delay_sec (РП52 «Дополнения» п. 2). */
  readonly lagging: boolean;
}

/** Состояние сборщика для /health: без обращения к базе — по последнему проходу этого процесса. */
export interface CollectorHealth {
  readonly last_pass_at: string | null;
  readonly lagging: boolean;
  readonly code?: "OPERATION_OUTCOME_LAGGING";
}

/**
 * Сборщик итогов (РП52 п. 1 (а)): проход по решённым отказам ADP в горизонте вне пути авторизации. Сбой записи — в
 * журнал процесса, запись остаётся без итога и берётся следующим проходом. Горизонт ограничивает только события: итог
 * агенту отдаёт GET из записи операции независимо от сборщика («Дополнения» п. 1).
 */
export class OperationOutcomeCollector {
  private readonly now: () => number;
  private readonly log: CollectorLog;
  private readonly startedMs: number;
  private lastPassMs: number | undefined;
  private lastLagging = false;

  constructor(
    private readonly store: OutcomeStore,
    private readonly opts: {
      readonly horizonSec: number;
      readonly maxDelaySec: number;
      readonly pushFor?: PushFor;
      readonly now?: () => number;
      readonly log?: CollectorLog;
    },
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.log = opts.log ?? (() => {});
    this.startedMs = this.now();
  }

  /** Отставание: проход не завершался дольше предела задержки или последний нашёл запись старше предела. */
  health(): CollectorHealth {
    const since = this.lastPassMs ?? this.startedMs;
    const lagging = this.lastLagging || this.now() - since > this.opts.maxDelaySec * 1000;
    return {
      last_pass_at: this.lastPassMs === undefined ? null : new Date(this.lastPassMs).toISOString(),
      lagging,
      ...(lagging ? { code: "OPERATION_OUTCOME_LAGGING" as const } : {}),
    };
  }

  /** Признак отставания: самая старая неразобранная запись в горизонте старше предела задержки. */
  async lagging(): Promise<boolean> {
    const nowMs = this.now();
    const oldest = await this.store.oldestPending(new Date(nowMs - this.opts.horizonSec * 1000).toISOString());
    return oldest !== undefined && Date.parse(oldest) < nowMs - this.opts.maxDelaySec * 1000;
  }

  async runOnce(): Promise<CollectorResult> {
    const nowMs = this.now();
    const since = new Date(nowMs - this.opts.horizonSec * 1000).toISOString();
    const at = new Date(nowMs).toISOString();
    let recorded = 0;
    let failed = 0;
    for (const op of await this.store.pending(since, OUTCOME_BATCH)) {
      const o = outcomeFromDecision(op, at);
      if (!o) continue;
      const event = eventFor(o, this.opts.pushFor);
      try {
        await this.store.record(o, event);
        recorded++;
        if (o.agent_code === null) this.log("info", { op_ref: o.op_ref, reason: o.reason }, "П8: итог операции без события — агент не установлен");
      } catch {
        failed++;
        this.log("warn", { op_ref: o.op_ref }, "П8: итог операции не записан");
      }
    }
    const lagging = await this.lagging();
    if (lagging) this.log("warn", { code: "OPERATION_OUTCOME_LAGGING" }, "П8: сборщик итогов отстаёт больше предела задержки");
    this.lastPassMs = this.now();
    this.lastLagging = lagging;
    return { recorded, failed, lagging };
  }
}

/** Проход сборщика по таймеру; останов ждёт идущий проход. */
export function startOutcomeCollector(collector: OperationOutcomeCollector, everyMs: number, onError: (err: unknown) => void): () => Promise<void> {
  let running: Promise<void> | undefined;
  const timer = setInterval(() => {
    if (running) return;
    running = collector
      .runOnce()
      .then(
        () => undefined,
        (err: unknown) => onError(err),
      )
      .finally(() => {
        running = undefined;
      });
  }, everyMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await running;
  };
}
