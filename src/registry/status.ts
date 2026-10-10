// Переходы статуса допуска (РП21 п. 4): ACTIVE ⇄ SUSPENDED с основанием A2 п. 7.1; EXCLUDED — конечный.
import {
  AGENT_STATUSES,
  EXCLUSION_GROUNDS,
  SUSPENSION_GROUNDS,
  isOneOf,
  type AgentStatus,
  type ExclusionGround,
  type SuspensionGround,
} from "./model.js";

export type StatusChange =
  | { readonly to: "SUSPENDED"; readonly ground: SuspensionGround }
  | { readonly to: "ACTIVE" }
  | { readonly to: "EXCLUDED"; readonly ground: ExclusionGround };

export class StatusTransitionError extends Error {
  constructor(
    readonly from: AgentStatus,
    readonly change: unknown,
  ) {
    super(`Переход статуса недопустим: ${from} → ${JSON.stringify(change)} (РП21 п. 4)`);
    this.name = "StatusTransitionError";
  }
}

/** Проверяет переход; неизвестный статус или основание — отказ, не догадка (инвариант 3). */
export function checkTransition(from: AgentStatus, change: unknown): StatusChange {
  const c = (typeof change === "object" && change !== null ? change : {}) as Record<string, unknown>;
  const to = Object.hasOwn(c, "to") ? c.to : undefined;
  const ground = Object.hasOwn(c, "ground") ? c.ground : undefined;
  if (!isOneOf(AGENT_STATUSES, from) || from === "EXCLUDED") throw new StatusTransitionError(from, change);
  if (to === "SUSPENDED" && from === "ACTIVE" && isOneOf(SUSPENSION_GROUNDS, ground)) return { to, ground };
  if (to === "ACTIVE" && from === "SUSPENDED" && ground === undefined) return { to };
  if (to === "EXCLUDED" && isOneOf(EXCLUSION_GROUNDS, ground)) return { to, ground };
  throw new StatusTransitionError(from, change);
}
