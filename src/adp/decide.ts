// П4 Точка решения ADP (ПИ-1, SPEC §6, РП43): BYPASS первой проверкой до любого ввода-вывода, затем проверки агентской
// операции по порядку §6; первая сработавшая даёт причину. Неподтверждённое состояние — отказ, не BYPASS (РП43 п. 4).
import { createHash } from "node:crypto";
import { canonicalJson, isCurrencyCode } from "@kuzin4u/agentic-core";
import type { CanonicalMessage, Decision } from "../shared/canonical.generated.js";
import type { DecisionReason } from "../shared/codes.js";
import type { Params } from "../shared/config.js";
import type { Mandate } from "../shared/pao.js";
import type { AgentRecord } from "../registry/model.js";
import { parseAgentCode } from "../registry/code.js";
import type { StateService } from "../state/index.js";
import { STATE_TO_PI, STATUS_TO_PI } from "./codes.js";
import type { OperationRecord, OperationStore } from "./operations.js";

/** Реестр агентов (П1): неизвестный — undefined; сбой — исключение (→ STATE_UNAVAILABLE). */
export interface AdpAgents {
  get(agent_code: string): Pick<AgentRecord, "status" | "level"> | undefined;
}

export type AdpMandate = Pick<Mandate, "status" | "type" | "merchant_scope" | "currency" | "amount_limit">;

/** Журнал согласий (П2): мандат агента со статусом по свёртке; чужой или неизвестный — undefined; сбой — исключение. */
export interface AdpMandates {
  get(mandate_id: string, agent_code: string): Promise<AdpMandate | undefined>;
}

export type AdpLog = (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;

export interface AdpOptions {
  readonly agents: AdpAgents;
  readonly mandates: AdpMandates;
  readonly state: Pick<StateService, "reserve" | "release" | "hold" | "amountLeft">;
  readonly operations: OperationStore;
  readonly params: Pick<Params, "aoi_rollout_phase" | "confirm_above_kop">;
  readonly log?: AdpLog;
  readonly clock?: () => number;
  readonly now?: () => Date;
}

/** Агентское сообщение некорректно (сумма, валюта, op_ref): не решение — ответ HTTP 400, у процессинга ADP_UNAVAILABLE. */
export class AdpRequestInvalid extends Error {
  constructor(readonly field: string) {
    super(`ADP: поле ${field} не по форме`);
    this.name = "AdpRequestInvalid";
  }
}

const AGENT_INSTRUMENTS: readonly string[] = ["AGENT_TOKEN", "ACCOUNT_LINK"];

/**
 * Неагентская операция ⇔ нет aoi и instrument.kind = CARD_TOKEN (ПИ-1, РП4). Только два поля сообщения: без хранилищ,
 * записи операции, идемпотентности и разбора остального тела (РП43 п. 1). aoi: null — как отсутствие признака.
 */
export function isBypass(msg: Pick<CanonicalMessage, "aoi" | "instrument">): boolean {
  return (msg.aoi === undefined || msg.aoi === null) && msg.instrument?.kind === "CARD_TOKEN";
}

/**
 * Хэш сообщения для повтора по op_ref: всё, кроме ts и seq — процессинг может переотправить ту же авторизацию с другим
 * временем; другая сумма, продавец, инструмент или признак — уже другое сообщение (РП43 п. 5).
 */
export function messageHash(msg: CanonicalMessage): string {
  const rest: Record<string, unknown> = { ...msg };
  delete rest.ts;
  delete rest.seq;
  return createHash("sha256").update(canonicalJson(rest)).digest("hex");
}

const BYPASS: Decision = Object.freeze({ decision: "BYPASS", reason: null, decided_in_ms: 0 });

/** Итог проверок агентской операции: отказ с причиной или одобрение с удержаниями. */
type Verdict =
  | { readonly reason: DecisionReason; readonly mandate_id: string | null }
  | {
      readonly reason: null;
      readonly mandate_id: string;
      readonly holds: readonly string[];
      readonly agent_level: number;
      readonly left?: number;
    };

const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;

export class Adp {
  private readonly log: AdpLog;
  private readonly clock: () => number;
  private readonly now: () => Date;
  /** Решения в работе по op_ref внутри процесса: одновременный повтор ждёт первое и получает его ответ. */
  private readonly inflight = new Map<string, Promise<Decision>>();

  constructor(private readonly opts: AdpOptions) {
    this.log = opts.log ?? (() => {});
    this.clock = opts.clock ?? (() => performance.now());
    this.now = opts.now ?? (() => new Date());
  }

  /** Решение по AUTH_REQUEST. Некорректное агентское сообщение — AdpRequestInvalid (не решение). */
  async decide(msg: CanonicalMessage): Promise<Decision> {
    if (isBypass(msg)) return BYPASS;
    const started = this.clock();
    const elapsed = () => Math.max(0, Math.round(this.clock() - started));
    if (typeof msg.op_ref !== "string" || msg.op_ref === "") throw new AdpRequestInvalid("op_ref");
    if (!isUnits(msg.amount)) throw new AdpRequestInvalid("amount");
    if (!isCurrencyCode(msg.currency)) throw new AdpRequestInvalid("currency");

    const running = this.inflight.get(msg.op_ref);
    if (running) {
      await running.catch(() => undefined);
      return this.decide(msg);
    }
    const p = this.decideOnce(msg, elapsed);
    this.inflight.set(msg.op_ref, p);
    try {
      return await p;
    } finally {
      this.inflight.delete(msg.op_ref);
    }
  }

  private async decideOnce(msg: CanonicalMessage, elapsed: () => number): Promise<Decision> {
    const msg_hash = messageHash(msg);
    let prior: OperationRecord | undefined;
    try {
      // Запись «в работе» до резерва (РП43 п. 5): к резерву по op_ref проходит только первый запрос.
      prior = await this.opts.operations.begin(msg.op_ref, msg_hash, this.now().toISOString());
    } catch {
      this.log("warn", { op_ref: msg.op_ref }, "ADP: запись операции не прочитана");
      return decline("STATE_UNAVAILABLE", elapsed());
    }
    if (prior) return { ...(await this.repeat(prior, msg_hash)), decided_in_ms: elapsed() };

    const v = await this.verdict(msg);
    const decision: Decision =
      v.reason === null
        ? {
            decision: "APPROVE",
            reason: null,
            reservation_id: v.holds[0] ?? null,
            agent_level: v.agent_level,
            ...(v.left === undefined ? {} : { mandate_left_after: v.left }),
            decided_in_ms: elapsed(),
          }
        : v.reason === "CONFIRMATION_REQUIRED"
          ? { decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED", decided_in_ms: elapsed() }
          : decline(v.reason, elapsed());
    try {
      await this.opts.operations.finish({
        op_ref: msg.op_ref,
        msg_hash,
        decision,
        mandate_id: v.mandate_id,
        holds: v.reason === null ? v.holds : [],
        at: this.now().toISOString(),
      });
    } catch {
      // Запись остаётся «в работе»: повтор op_ref получит STATE_UNAVAILABLE без нового резерва; решение не меняется.
      this.log("warn", { op_ref: msg.op_ref }, "ADP: запись операции не сохранена");
    }
    return decision;
  }

  /** Повтор op_ref (ПИ-1): тот же хэш — прежнее решение; у APPROVE удержание должно держать бюджет (инвариант 4). */
  private async repeat(prior: OperationRecord, msg_hash: string): Promise<Decision> {
    if (prior.msg_hash !== msg_hash) {
      this.log("warn", { op_ref: prior.op_ref, incident: true }, "ADP: повтор op_ref с другим сообщением");
      return decline("STATE_UNAVAILABLE", 0);
    }
    if (prior.decision === null) {
      // В работе на другом экземпляре или решение не сохранено: прежнего ответа нет, нового резерва не делаем.
      this.log("warn", { op_ref: prior.op_ref }, "ADP: повтор op_ref — решение ещё не записано");
      return decline("STATE_UNAVAILABLE", 0);
    }
    if (prior.decision.decision !== "APPROVE") return prior.decision;
    for (const hold_id of prior.holds) {
      const h = await this.opts.state.hold(hold_id);
      if (!h.ok) {
        this.log("warn", { op_ref: prior.op_ref, hold_id, code: h.code }, "ADP: повтор APPROVE — удержание не держит бюджет");
        return decline("STATE_UNAVAILABLE", 0);
      }
    }
    return prior.decision;
  }

  /** Проверки агентской операции по порядку SPEC §6; первая сработавшая — причина. */
  private async verdict(msg: CanonicalMessage): Promise<Verdict> {
    const kind: string | undefined = msg.instrument?.kind;
    const agentInstrument = kind !== undefined && AGENT_INSTRUMENTS.includes(kind);
    const aoi = msg.aoi ?? undefined;
    const no = (reason: DecisionReason, mandate_id: string | null = null): Verdict => ({ reason, mandate_id });

    // 1. Признак (A1 п. 3.2). Неизвестный вид инструмента без aoi — не «известно неагентская» (РП43 п. 1).
    if (aoi === undefined) {
      if (!agentInstrument) {
        this.log("warn", { op_ref: msg.op_ref, kind, incident: true }, "ADP: неизвестный вид инструмента без признака");
        return no("AOI_MISSING");
      }
      // 1а. Агентский инструмент без признака: очередь 3 — обязательный отказ (A1 п. 8.3); 1–2 — домен токена, PS-14.
      return no(this.opts.params.aoi_rollout_phase === 3 ? "AOI_MISSING" : "CREDENTIAL_INVALID");
    }
    if (aoi.indicator !== true || !wellFormedCode(aoi.agent_code)) return no("AOI_MISSING");
    const agent_code = aoi.agent_code;

    // 2, 4. Домен токена и криптограмма — PS-14; до него не подтверждено (РП43 п. 7). Неизвестный вид с aoi — то же.
    if (kind !== "CARD_TOKEN") return no("CREDENTIAL_INVALID");

    // 3. Агент — из реестра (инвариант 5). Исключённый — вне реестра (A1 п. 5.3); сбой реестра — не подтверждено.
    let agent: Pick<AgentRecord, "status" | "level"> | undefined;
    try {
      agent = this.opts.agents.get(agent_code);
    } catch {
      this.log("warn", { op_ref: msg.op_ref }, "ADP: реестр агентов не прочитан");
      return no("STATE_UNAVAILABLE");
    }
    if (!agent || agent.status === "EXCLUDED") return no("AGENT_UNKNOWN");
    if (agent.status === "SUSPENDED") return no("AGENT_SUSPENDED");

    // 5. Мандат агента (чужой = неизвестный), статус — по свёртке журнала (инвариант 5).
    const mandate_id = aoi.mandate_id;
    if (typeof mandate_id !== "string" || mandate_id === "") return no("MANDATE_NOT_FOUND");
    const m = await this.mandate(mandate_id, agent_code, msg.op_ref);
    if (m === "unavailable") return no("STATE_UNAVAILABLE", mandate_id);
    if (!m) return no("MANDATE_NOT_FOUND", mandate_id);
    const statusReason = this.statusReason(m);
    if (statusReason) return no(statusReason, mandate_id);

    // 6. Продавец и валюта — в области мандата; MCC — по домену токена (PS-14).
    const merchant = msg.merchant?.id;
    if (merchant === undefined || !m.merchant_scope.includes(merchant)) return no("MANDATE_SCOPE", mandate_id);
    if (msg.currency !== m.currency) return no("MANDATE_SCOPE", mandate_id);

    // CART — два резерва с родителем INTENT (РП43 п. 6, К1.4); до них не одобряем без проверки родителя.
    if (m.type === "CART") return no("STATE_UNAVAILABLE", mandate_id);

    // 9–10. Порог подтверждения до PS-13: подтверждение проверить нечем — CONFIRMATION_REQUIRED (РП43 п. 7). Резерв под
    // такой ответ не держим; остаток (проверки 7–8, идут раньше) — чтением без резерва, не подтверждён — отказ.
    if (msg.amount > this.opts.params.confirm_above_kop) {
      const left = await this.opts.state.amountLeft(mandate_id, m.amount_limit);
      if (left === undefined) return no("STATE_UNAVAILABLE", mandate_id);
      return no(left < msg.amount ? "LIMIT_EXCEEDED" : "CONFIRMATION_REQUIRED", mandate_id);
    }

    // 7–8, 11. Резерв: разовая сумма и остаток — одно атомарное условие ядра; op_key — op_ref (РП43 п. 5).
    const money = { amount: msg.amount, currency: msg.currency };
    const r = await this.opts.state.reserve(mandate_id, money, msg.op_ref, { waitExhausted: false });
    if (!r.ok) {
      const reason = STATE_TO_PI[r.code];
      if (reason === "INVALID") throw new AdpRequestInvalid("amount");
      if (r.code === "IDEMPOTENCY_CONFLICT") {
        this.log("warn", { op_ref: msg.op_ref, mandate_id, incident: true }, "ADP: резерв по op_ref с другой суммой");
      }
      return no(reason, mandate_id);
    }

    // 12. Сверка статуса после резерва (РП43 п. 5): отзыв в окне между чтением и резервом — освобождение и отказ.
    // Момент авторизации для A3 п. 6.3 — это чтение; отзыв после него — «после авторизации».
    const after = await this.mandate(mandate_id, agent_code, msg.op_ref);
    const late = after === "unavailable" || !after ? "STATE_UNAVAILABLE" : this.statusReason(after);
    if (late) {
      await this.release(r.hold.id, msg.op_ref);
      return no(late, mandate_id);
    }
    const left = await this.opts.state.amountLeft(mandate_id, m.amount_limit);
    return {
      reason: null,
      mandate_id,
      holds: [r.hold.id],
      agent_level: agent.level,
      ...(left === undefined ? {} : { left }),
    };
  }

  private async mandate(id: string, agent_code: string, op_ref: string): Promise<AdpMandate | undefined | "unavailable"> {
    try {
      return await this.opts.mandates.get(id, agent_code);
    } catch {
      this.log("warn", { op_ref, mandate_id: id }, "ADP: журнал согласий не прочитан");
      return "unavailable";
    }
  }

  /** null — ACTIVE; иначе причина по статусу. Статус не определён — не подтверждено. */
  private statusReason(m: AdpMandate): DecisionReason | null {
    if (m.status === "ACTIVE") return null;
    // Статус вне перечня (данные, а не тип) — не подтверждено, а не «действует» (инвариант 3).
    return (m.status === undefined ? undefined : STATUS_TO_PI[m.status]) ?? "STATE_UNAVAILABLE";
  }

  /** Сбой освобождения отказ не меняет: удержание держит бюджет до прохода expire (безопасная сторона). */
  private async release(hold_id: string, op_ref: string): Promise<void> {
    const r = await this.opts.state.release(hold_id);
    if (!r.ok) this.log("warn", { op_ref, hold_id, code: r.code }, "ADP: удержание не освобождено — до прохода expire");
  }
}

const decline = (reason: DecisionReason, decided_in_ms: number): Decision => ({ decision: "DECLINE", reason, decided_in_ms });

function wellFormedCode(v: unknown): v is string {
  try {
    parseAgentCode(v);
    return true;
  } catch {
    return false;
  }
}
