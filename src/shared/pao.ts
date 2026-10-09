// Типы схем ПАО — из agentic-core как есть (К5); таблица ошибок — из своего agent-protocol.yaml (РП16).
// Типы core v0.2.0 сгенерированы из ПАО 1.1.0, спецификация Платформы — 1.2.0: расхождение №7 в STATUS.
import type { ErrorCode as CoreErrorCode } from "@kuzin4u/agentic-core/pao";
import type { PaoErrorCode } from "./pao-errors.generated.js";

export type * from "@kuzin4u/agentic-core/pao";
export { PAO_VERSION as CORE_PAO_VERSION } from "@kuzin4u/agentic-core/pao";

// Сборка падает, если набор кодов ошибок в core разойдётся с x-pao-errors Платформы.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
export const ERROR_CODES_MATCH_CORE: Same<CoreErrorCode, PaoErrorCode> = true;
