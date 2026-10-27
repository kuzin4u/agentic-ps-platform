// Приостановление и снятие приостановления агента (РП54, PS-17): одно действие оператора Системы — смена статуса по
// РП21 п. 4 и событие agent.suspended / agent.reinstated. Реестр на PG (РП64 п. 4) — статус и событие одной транзакцией
// (AgentStatusTx). В памяти — статус первым: с этого момента отказывают ADP (п. 3) и шлюз ПАО; событие — следом, общей
// транзакции нет (РП54 п. 2). HTTP-метода оператора нет — PS-32; на стенде — stand.suspendAgent / stand.reinstateAgent.
import type { AgentStatusEventDraft } from "../pao/events.js";
import type { AgentRecord } from "./model.js";
import { AgentNotFoundError, type AgentRegistry } from "./registry.js";

/** Лента для событий статуса: повтор той же смены — false, без второго события (РП54 п. 2). */
export interface AgentStatusEvents {
  appendAgentStatusEvent(draft: AgentStatusEventDraft, at: string): Promise<boolean>;
}

/** Действие оператора: приостановить с основанием A2 п. 7.1 или снять приостановление. */
export type AgentStatusRequest = { readonly to: "SUSPENDED"; readonly ground: unknown } | { readonly to: "ACTIVE" };

/**
 * Статус и событие agent.* одной транзакцией (РП64 п. 4) — реестр на PG. Нет агента — AgentNotFoundError, недопустимый
 * переход — StatusTransitionError; событие новой версии не вставилось — AgentStatusEventConflictError и откат.
 */
export interface AgentStatusTx {
  transitStatus(agent_code: string, req: AgentStatusRequest): Promise<{ readonly record: AgentRecord; readonly written: boolean }>;
}

export interface AgentStatusServiceDeps {
  readonly events: AgentStatusEvents;
  /** Строка попытки push в той же записи: agent.suspended — и при SUSPENDED (РП54 п. 9, pushAllowed). */
  readonly pushFor: (agent_code: string, type: AgentStatusEventDraft["type"]) => Promise<boolean>;
  /** Реестр на PG: смена статуса с событием одной транзакцией; тогда events и pushFor не используются. */
  readonly tx?: AgentStatusTx;
  readonly log?: (level: "info" | "warn" | "error", fields: Record<string, unknown>, msg: string) => void;
}

/**
 * Повтор действия в достигнутом статусе (РП54 п. 2): приостановление — уже SUSPENDED с тем же основанием; снятие — уже
 * ACTIVE после приостановления (suspended_at есть: в ACTIVE после приостановления ведёт только снятие). По смыслу, не по
 * версии записи (КТ1 № 3).
 */
export const isStatusRepeat = (cur: AgentRecord, req: AgentStatusRequest): boolean =>
  req.to === "SUSPENDED" ? cur.status === "SUSPENDED" && cur.status_ground === req.ground : cur.status === "ACTIVE" && cur.suspended_at !== null;

/** Событие новой версии статуса уже есть — статус не меняется (откат), повтор — заново (РП64 п. 4). */
export class AgentStatusEventConflictError extends Error {
  constructor(
    readonly agent_code: string,
    readonly version: number,
  ) {
    super(`AGENT_STATUS_EVENT_CONFLICT: ${agent_code} v${version}`);
    this.name = "AgentStatusEventConflictError";
  }
}

/** Статус сменён, событие не записано (РП54 п. 2): статус действует, повтор того же действия дописывает событие. */
export class AgentStatusEventMissingError extends Error {
  constructor(
    readonly agent_code: string,
    readonly record: AgentRecord,
    options?: { cause?: unknown },
  ) {
    super(`AGENT_STATUS_EVENT_MISSING: ${agent_code}`, options);
    this.name = "AgentStatusEventMissingError";
  }
}

export class AgentStatusService {
  constructor(
    private readonly registry: AgentRegistry,
    private readonly deps: AgentStatusServiceDeps,
  ) {}

  /**
   * ACTIVE → SUSPENDED с основанием A2 п. 7.1 (РП21 п. 4). Уже SUSPENDED с тем же основанием — повтор: статус не
   * меняется, недостающее событие дописывается; с другим основанием — StatusTransitionError (как неизвестное).
   */
  async suspend(agent_code: string, ground: unknown): Promise<AgentRecord> {
    return this.apply(agent_code, { to: "SUSPENDED", ground }, "agent.suspended");
  }

  /** SUSPENDED → ACTIVE без основания. Уже ACTIVE после приостановления — повтор; ACTIVE с допуска — StatusTransitionError. */
  async reinstate(agent_code: string): Promise<AgentRecord> {
    return this.apply(agent_code, { to: "ACTIVE" }, "agent.reinstated");
  }

  private async apply(agent_code: string, req: AgentStatusRequest, type: AgentStatusEventDraft["type"]): Promise<AgentRecord> {
    if (this.deps.tx) {
      // Одна транзакция (РП64 п. 4): сбой — ничего не изменено, ошибка оператору, повтор — заново.
      const { record, written } = await this.deps.tx.transitStatus(agent_code, req);
      this.deps.log?.("info", { agent_code, type, version: record.row_version, written }, "П1: статус агента сменён");
      return record;
    }
    const cur = await this.current(agent_code);
    const rec = isStatusRepeat(cur, req) ? cur : await this.registry.changeStatus(agent_code, req);
    await this.emit(rec, type);
    return rec;
  }

  private async current(agent_code: string): Promise<AgentRecord> {
    const cur = await this.registry.get(agent_code);
    if (!cur) throw new AgentNotFoundError(agent_code);
    return cur;
  }

  /** Событие смены: event_id и время — от записи реестра, поэтому повтор пишет то же событие или ничего (РП54 п. 2). */
  private async emit(rec: AgentRecord, type: AgentStatusEventDraft["type"]): Promise<void> {
    let written: boolean;
    try {
      // Строка push — чтением реестра: его сбой — как сбой записи события (статус остаётся, повтор дописывает).
      const draft: AgentStatusEventDraft = {
        agent_code: rec.agent_code,
        type,
        data: { agent_code: rec.agent_code },
        version: rec.row_version,
        push: await this.deps.pushFor(rec.agent_code, type),
      };
      written = await this.deps.events.appendAgentStatusEvent(draft, rec.status_changed_at);
    } catch (err) {
      // Статус остаётся (fail-closed): агент остановлен 403 и отказом ADP, без события — только задержка сигнала.
      this.deps.log?.(
        "error",
        { agent_code: rec.agent_code, type, version: rec.row_version, incident: true, code: "AGENT_STATUS_EVENT_MISSING" },
        "П1: статус агента сменён, событие не записано — повторите действие",
      );
      throw new AgentStatusEventMissingError(rec.agent_code, rec, { cause: err });
    }
    this.deps.log?.("info", { agent_code: rec.agent_code, type, version: rec.row_version, written }, "П1: статус агента сменён");
  }
}
