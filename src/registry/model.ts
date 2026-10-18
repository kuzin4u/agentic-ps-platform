// Запись реестра агентов (A2, РП17, РП21). Сведений о принципалах нет (A2 п. 1.2), номера карты нет (инвариант 1).
import type { AgentSelf } from "../shared/pao.js";

/** Классы агентов (A2 п. 2.1–2.4) — перечень AgentSelf.class ПАО. */
export const AGENT_CLASSES = ["BUYER", "SELLER", "SURFACE", "SERVICE"] as const;
export type AgentClass = (typeof AGENT_CLASSES)[number];

/** Статусы допуска — перечень AgentSelf.status ПАО. */
export const AGENT_STATUSES = ["ACTIVE", "SUSPENDED", "EXCLUDED"] as const;
export type AgentStatus = (typeof AGENT_STATUSES)[number];

/** Закрытый перечень оснований отказа в допуске (РП21 п. 2, РП23 п. 2). */
export const ADMISSION_REFUSALS = [
  "APPLICATION_INCOMPLETE",
  "CLASS_UNKNOWN",
  "CODE_INVALID",
  "CODE_TAKEN",
  "PRINCIPAL_DATA",
  "CONFORMANCE_MISSING",
  "AGENT_CARD_MISMATCH",
  "KEY_INVALID",
] as const;
export type AdmissionRefusal = (typeof ADMISSION_REFUSALS)[number];

/** Основания приостановления (A2 п. 7.1, РП21 п. 4). */
export const SUSPENSION_GROUNDS = [
  "KEY_COMPROMISE",
  "OUT_OF_MANDATE",
  "FALSE_INFORMATION",
  "INCIDENT_EVASION",
] as const;
export type SuspensionGround = (typeof SUSPENSION_GROUNDS)[number];

/** Основания исключения: те же и отказ оператора агента от допуска (РП21 п. 4). */
export const EXCLUSION_GROUNDS = [...SUSPENSION_GROUNDS, "WITHDRAWN"] as const;
export type ExclusionGround = (typeof EXCLUSION_GROUNDS)[number];

/** Песочница — допуск по заявлению для прохождения набора; контур оператора — только с набором (РП17). */
export type Contour = "sandbox" | "operator";

/** Уровень при допуске (РП21 п. 3, ПС01). */
export const ADMISSION_LEVEL = 1;

export interface AgentRecord {
  readonly agent_code: string;
  readonly issuer: string;
  readonly id: string;
  readonly version: number;
  readonly operator: string;
  readonly class: AgentClass;
  readonly level: number;
  readonly status: AgentStatus;
  /** Основание последнего перехода статуса; у ACTIVE после допуска — null. */
  readonly status_ground: SuspensionGround | ExclusionGround | null;
  readonly model: string;
  readonly runtime: string;
  readonly contour: Contour;
  /** Ссылка на прогон набора соответствия; в ПАО не передаётся (РП17). */
  readonly conformance_run_ref: string | null;
  readonly admitted_at: string;
  readonly status_changed_at: string;
  /** Версия строки: каждое изменение записи увеличивает её на 1; изменение — по условию версии. */
  readonly row_version: number;
}

/** Подписка на события в записи агента (РП40 п. 1, SECURITY С6): заменяется целиком; пустой events — push выключен. */
export interface AgentSubscription {
  readonly url: string;
  readonly events: readonly NonNullable<import("../shared/pao.js").Event["type"]>[];
}

// Сборка падает, если перечни разойдутся с ПАО.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
export const CLASSES_MATCH_PAO: Same<AgentClass, NonNullable<AgentSelf["class"]>> = true;
export const STATUSES_MATCH_PAO: Same<AgentStatus, NonNullable<AgentSelf["status"]>> = true;

export const isOneOf = <T extends string>(list: readonly T[], v: unknown): v is T =>
  typeof v === "string" && (list as readonly string[]).includes(v);
