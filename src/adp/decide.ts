// П4 Точка решения ADP (ПИ-1, SPEC §6, РП43): BYPASS первой проверкой до любого ввода-вывода, затем проверки агентской
// операции по порядку §6; первая сработавшая даёт причину. Неподтверждённое состояние — отказ, не BYPASS (РП43 п. 4).
import type {
  CanonicalMessage,
  Decision,
} from "../shared/canonical.generated.js";
import type { DecisionReason } from "../shared/codes.js";
import type { Params } from "../shared/config.js";
import type { AgentRecord } from "../registry/model.js";
import { parseAgentCode } from "../registry/code.js";

/** Реестр агентов (П1): неизвестный — undefined; сбой — исключение (→ STATE_UNAVAILABLE). */
export interface AdpAgents {
  get(agent_code: string): Pick<AgentRecord, "status" | "level"> | undefined;
}

export type AdpLog = (
  level: "info" | "warn",
  fields: Record<string, unknown>,
  msg: string,
) => void;

export interface AdpOptions {
  readonly agents: AdpAgents;
  readonly params: Pick<Params, "aoi_rollout_phase">;
  readonly log?: AdpLog;
  readonly clock?: () => number;
}

const AGENT_INSTRUMENTS: readonly string[] = ["AGENT_TOKEN", "ACCOUNT_LINK"];

/**
 * Неагентская операция ⇔ нет aoi и instrument.kind = CARD_TOKEN (ПИ-1, РП4). Только два поля сообщения: без хранилищ,
 * записи операции, идемпотентности и разбора остального тела (РП43 п. 1). aoi: null — как отсутствие признака.
 */
export function isBypass(
  msg: Pick<CanonicalMessage, "aoi" | "instrument">,
): boolean {
  return (
    (msg.aoi === undefined || msg.aoi === null) &&
    msg.instrument?.kind === "CARD_TOKEN"
  );
}

const BYPASS: Decision = Object.freeze({
  decision: "BYPASS",
  reason: null,
  decided_in_ms: 0,
});

export class Adp {
  private readonly log: AdpLog;
  private readonly clock: () => number;

  constructor(private readonly opts: AdpOptions) {
    this.log = opts.log ?? (() => {});
    this.clock = opts.clock ?? (() => performance.now());
  }

  async decide(msg: CanonicalMessage): Promise<Decision> {
    if (isBypass(msg)) return BYPASS;
    const started = this.clock();
    const reason = await this.agentic(msg);
    return {
      decision: "DECLINE",
      reason,
      decided_in_ms: Math.max(0, Math.round(this.clock() - started)),
    };
  }

  /** Агентская операция: проверки SPEC §6 по порядку; первая сработавшая — причина отказа. */
  private async agentic(msg: CanonicalMessage): Promise<DecisionReason> {
    const kind: string | undefined = msg.instrument?.kind;
    const agentInstrument =
      kind !== undefined && AGENT_INSTRUMENTS.includes(kind);
    const aoi = msg.aoi ?? undefined;

    // 1. Признак (A1 п. 3.2). Неизвестный вид инструмента без aoi — не «известно неагентская» (РП43 п. 1).
    if (aoi === undefined) {
      if (!agentInstrument) {
        this.log(
          "warn",
          { op_ref: msg.op_ref, kind, incident: true },
          "ADP: неизвестный вид инструмента без признака",
        );
        return "AOI_MISSING";
      }
      // 1а. Агентский инструмент без признака: очередь 3 — обязательный отказ (A1 п. 8.3); 1–2 — домен токена, PS-14.
      return this.opts.params.aoi_rollout_phase === 3
        ? "AOI_MISSING"
        : "CREDENTIAL_INVALID";
    }
    if (aoi.indicator !== true || !wellFormedCode(aoi.agent_code))
      return "AOI_MISSING";

    // 3. Агент — из реестра (инвариант 5). Исключённый — вне реестра (A1 п. 5.3); сбой реестра — не подтверждено.
    let agent: Pick<AgentRecord, "status" | "level"> | undefined;
    try {
      agent = this.opts.agents.get(aoi.agent_code);
    } catch {
      this.log(
        "warn",
        { op_ref: msg.op_ref },
        "ADP: реестр агентов не прочитан",
      );
      return "STATE_UNAVAILABLE";
    }
    if (!agent || agent.status === "EXCLUDED") return "AGENT_UNKNOWN";
    if (agent.status === "SUSPENDED") return "AGENT_SUSPENDED";

    // 2, 4. Домен токена и криптограмма — PS-14; до него не подтверждено (РП43 п. 7). Неизвестный вид с aoi — то же.
    if (kind !== "CARD_TOKEN") return "CREDENTIAL_INVALID";

    // 5–12 — мандат, область, резерв (К1.3). До них — не подтверждено.
    return "STATE_UNAVAILABLE";
  }
}

function wellFormedCode(v: unknown): v is string {
  try {
    parseAgentCode(v);
    return true;
  } catch {
    return false;
  }
}
