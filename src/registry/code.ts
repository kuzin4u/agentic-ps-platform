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

const PART = /^[a-z0-9-]+$/;
const VERSION = /^v([1-9][0-9]{0,8})$/;

export function parseAgentCode(raw: unknown): AgentCode {
  if (typeof raw !== "string") throw new AgentCodeError(raw);
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
