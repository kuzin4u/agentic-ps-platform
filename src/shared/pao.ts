// Типы схем ПАО — из agentic-core как есть (К5); таблица ошибок — из своего agent-protocol.yaml (РП16).
// Версия ПАО и таблица ошибок core сверяются с Платформой в tests/contract/pao-errors.test.ts.
import type { ErrorCode as CoreErrorCode } from "@kuzin4u/agentic-core/pao";
import type { PaoErrorCode } from "./pao-errors.generated.js";

export type * from "@kuzin4u/agentic-core/pao";
export {
  PAO_VERSION as CORE_PAO_VERSION,
  PAO_ERRORS as CORE_PAO_ERRORS,
} from "@kuzin4u/agentic-core/pao";

// Сборка падает, если набор кодов ошибок в core разойдётся с x-pao-errors Платформы.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
export const ERROR_CODES_MATCH_CORE: Same<CoreErrorCode, PaoErrorCode> = true;
