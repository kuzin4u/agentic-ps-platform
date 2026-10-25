// Код агента «выдавшая сторона : идентификатор : версия» (A2 п. 4.1–4.2, РП21 п. 1).
// Части через «:», каждая [a-z0-9-]+; последняя — v<N>, предпоследняя — идентификатор, остальные — сторона.

export interface AgentCode {
  readonly code: string;
  readonly issuer: string;
  readonly id: string;
  readonly version: number;
}

export class AgentCodeError extends Error {
  constructor(readonly value: unknown) {
    super(`Код агента не по грамматике РП21: ${JSON.stringify(value)}`);
    this.name = "AgentCodeError";
  }
}

/** Единственная выдавшая сторона кода — оператор реестра Платформы (РП23 п. 1); другая — CODE_INVALID при допуске. */
export const REGISTRY_ISSUER = "nspk:agent";

/**
 * Наибольшая длина кода (РП63 п. 11; № 43): не длиннее транспортного предела параметра пути MAX_PATH_PARAM_LENGTH
 * (src/server.ts), иначе продавец не прочитает статус по GET /merchants/v1/agents/{code} (414). Равенство — тестом:
 * импорт из server.ts дал бы цикл.
 */
export const AGENT_CODE_MAX_LENGTH = 256;

const PART = /^[a-z0-9-]+$/;
const VERSION = /^v([1-9][0-9]{0,8})$/;

export function parseAgentCode(raw: unknown): AgentCode {
  // Длиннее предела — не код: при допуске CODE_INVALID, при чтении — как неизвестный (404 / AGENT_UNKNOWN).
  if (typeof raw !== "string" || raw.length > AGENT_CODE_MAX_LENGTH) throw new AgentCodeError(raw);
  const parts = raw.split(":");
  if (parts.length < 3 || !parts.every((p) => PART.test(p))) throw new AgentCodeError(raw);
  const m = VERSION.exec(parts[parts.length - 1] as string);
  if (!m) throw new AgentCodeError(raw);
  return Object.freeze({
    code: raw,
    issuer: parts.slice(0, -2).join(":"),
    id: parts[parts.length - 2] as string,
    version: Number(m[1]),
  });
}

export const isAgentCode = (raw: unknown): boolean => {
  try {
    parseAgentCode(raw);
    return true;
  } catch {
    return false;
  }
};
