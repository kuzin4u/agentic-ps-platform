// Приостановление и снятие приостановления агента (РП54, PS-17): одно действие оператора Системы — смена статуса по
// РП21 п. 4 и событие agent.suspended / agent.reinstated. Статус — первым: с этого момента отказывают ADP (п. 3) и шлюз
// ПАО; событие — следом. Реестр в памяти, лента — в своём хранилище: общей транзакции нет (РП54 п. 2). HTTP-метода
// оператора нет — PS-32; на стенде — stand.suspendAgent / stand.reinstateAgent.
import type { AgentStatusEventDraft } from "../pao/events.js";
import type { AgentRecord } from "./model.js";
import { AgentNotFoundError, type AgentRegistry } from "./registry.js";

/** Лента для событий статуса: повтор той же смены — false, без второго события (РП54 п. 2). */
export interface AgentStatusEvents {
  appendAgentStatusEvent(draft: AgentStatusEventDraft, at: string): Promise<boolean>;
}

export interface AgentStatusServiceDeps {
  readonly events: AgentStatusEvents;
  /** Строка попытки push в той же записи: agent.suspended — и при SUSPENDED (РП54 п. 9, pushAllowed). */
  readonly pushFor: (agent_code: string, type: AgentStatusEventDraft["type"]) => boolean;
  readonly log?: (level: "info" | "warn" | "error", fields: Record<string, unknown>, msg: string) => void;
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
    const cur = this.current(agent_code);
    const repeat = cur.status === "SUSPENDED" && cur.status_ground === ground;
    const rec = repeat ? cur : this.registry.changeStatus(agent_code, { to: "SUSPENDED", ground });
    await this.emit(rec, "agent.suspended");
    return rec;
  }

  /**
   * SUSPENDED → ACTIVE без основания. Уже ACTIVE после снятия (версия записи > 1: в ACTIVE после допуска ведёт только
   * снятие) — повтор с дописыванием события; ACTIVE с допуска — StatusTransitionError.
   */
  async reinstate(agent_code: string): Promise<AgentRecord> {
    const cur = this.current(agent_code);
    const repeat = cur.status === "ACTIVE" && cur.row_version > 1;
    const rec = repeat ? cur : this.registry.changeStatus(agent_code, { to: "ACTIVE" });
    await this.emit(rec, "agent.reinstated");
    return rec;
  }

  private current(agent_code: string): AgentRecord {
    const cur = this.registry.get(agent_code);
    if (!cur) throw new AgentNotFoundError(agent_code);
    return cur;
  }

  /** Событие смены: event_id и время — от записи реестра, поэтому повтор пишет то же событие или ничего (РП54 п. 2). */
  private async emit(rec: AgentRecord, type: AgentStatusEventDraft["type"]): Promise<void> {
    const draft: AgentStatusEventDraft = {
      agent_code: rec.agent_code,
      type,
      data: { agent_code: rec.agent_code },
      version: rec.row_version,
      push: this.deps.pushFor(rec.agent_code, type),
    };
    let written: boolean;
    try {
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
