// П9 Лента событий агенту (РП39, PS-08 К1.2): событие пишется в одной транзакции с записью журнала согласий (Outbox),
// номер у агента — под блокировкой агента до фиксации. Событие без подписи до ПАО 1.5.0 — сигнал, статус — через GET.
// Второй источник — переход запроса подтверждения П6 (РП51 п. 1–4): та же лента и номер, без записи журнала.
// Третий — итог операции П8 (РП52 п. 7): operation.authorized / .declined, а с клиринга — .settled (РП53 п. 9), с возврата —
// .refunded (РП55 п. 3); data — только {op_ref}.
// Четвёртый — смена статуса допуска агента П1 (РП54 п. 8): agent.suspended / .reinstated; data — только {agent_code}.
import { createHash } from "node:crypto";
import type { AgentStatus } from "../registry/model.js";
import type { Event } from "../shared/pao.js";

export type PaoEventType = Event["type"];

/** Что пишется вместе с записью журнала: кому и о чём. Номер, event_id и время даёт запись (РП39 п. 2–4). */
export interface EventDraft {
  readonly agent_code: string;
  readonly type: PaoEventType;
  /** Только ссылки, без предмета, сумм и статуса (A7 п. 8.3, РП39 п. 5, РП51 п. 5). */
  readonly data: EventData;
  /** Строка попытки push в той же транзакции (РП40 п. 5): агент ACTIVE и подписан на тип — на момент записи. */
  readonly push?: boolean;
}

/**
 * Ссылка события: мандат (запись журнала), запрос подтверждения (переход П6, РП51 п. 5), операция (итог П8, РП52 п. 7)
 * или агент (смена статуса П1, РП54 п. 8).
 */
export type EventData =
  | { readonly mandate_id: string }
  | { readonly confirmation_id: string }
  | { readonly op_ref: string }
  | { readonly agent_code: string };

/** Событие перехода запроса подтверждения: тип confirmation.*, data — только {confirmation_id} (РП51 п. 2, 5). */
export interface ConfirmationEventDraft extends EventDraft {
  readonly type: Extract<PaoEventType, `confirmation.${string}`>;
  readonly data: { readonly confirmation_id: string };
}

/**
 * Событие итога операции, клиринга и возврата: operation.authorized / .declined / .settled / .refunded, data — только
 * {op_ref} (РП52 п. 7, РП53 п. 9, РП55 п. 3).
 */
export interface OperationEventDraft extends EventDraft {
  readonly type: Extract<PaoEventType, "operation.authorized" | "operation.declined" | "operation.settled" | "operation.refunded">;
  readonly data: { readonly op_ref: string };
}

/**
 * Событие смены статуса допуска: agent.suspended / .reinstated, data — только {agent_code}, без основания (РП54 п. 8).
 * version — row_version записи реестра после смены: по ней event_id и UNIQUE (agent_code, agent_status_version).
 */
export interface AgentStatusEventDraft extends EventDraft {
  readonly type: Extract<PaoEventType, "agent.suspended" | "agent.reinstated">;
  readonly data: { readonly agent_code: string };
  readonly version: number;
}

/**
 * Строка ленты: событие и его источник — запись журнала (внешний ключ в PostgreSQL) или запрос подтверждения (РП51 п. 1);
 * у события подтверждения пара журнала — null.
 */
export interface StoredEvent extends Omit<EventDraft, "push"> {
  readonly seq: number;
  readonly event_id: string;
  readonly at: string;
  readonly journal_chain: string | null;
  readonly journal_seq: number | null;
}

export const EVENT_ID_DOMAIN = "pao:event-id:v1";
export const CONFIRMATION_EVENT_ID_DOMAIN = "pao:confirmation-event-id:v1";
export const OPERATION_EVENT_ID_DOMAIN = "pao:operation-event-id:v1";
export const AGENT_STATUS_EVENT_ID_DOMAIN = "pao:agent-status-event-id:v1";
export const EVENT_SEQ_LOCK_DOMAIN = "pao:event-seq-lock:v1";

export const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** event_id от записи журнала (РП39 п. 4): `evt_` + UUID v8 (RFC 9562 §5.8) — у одной записи один id на всех экземплярах. */
export function eventIdFor(chain: string, seq: number): string {
  if (chain === "" || chain.includes("\n") || !Number.isSafeInteger(seq) || seq < 1) throw new Error("eventIdFor: запись журнала");
  return uuidV8(`${EVENT_ID_DOMAIN}\n${chain}\n${seq}`);
}

/** event_id перехода запроса подтверждения (РП51 п. 4): своя метка — не совпадает с событием записи журнала. */
export function confirmationEventIdFor(confirmation_id: string, type: ConfirmationEventDraft["type"]): string {
  if (confirmation_id === "" || confirmation_id.includes("\n")) throw new Error("confirmationEventIdFor: запрос подтверждения");
  return uuidV8(`${CONFIRMATION_EVENT_ID_DOMAIN}\n${confirmation_id}\n${type}`);
}

/** event_id итога операции (РП52 п. 7): своя метка — не совпадает с событиями журнала и подтверждений. */
export function operationEventIdFor(op_ref: string, type: OperationEventDraft["type"]): string {
  if (op_ref === "" || op_ref.includes("\n")) throw new Error("operationEventIdFor: операция");
  return uuidV8(`${OPERATION_EVENT_ID_DOMAIN}\n${op_ref}\n${type}`);
}

/** event_id смены статуса агента (РП54 п. 2): от версии записи реестра — повтор действия даёт тот же id. */
export function agentStatusEventIdFor(agent_code: string, version: number): string {
  if (agent_code === "" || agent_code.includes("\n") || !Number.isSafeInteger(version) || version < 2) {
    throw new Error("agentStatusEventIdFor: смена статуса агента");
  }
  return uuidV8(`${AGENT_STATUS_EVENT_ID_DOMAIN}\n${agent_code}\n${version}`);
}

/**
 * Push по событию (РП40 п. 5–7, РП54 п. 9): агенту ACTIVE; при SUSPENDED — только agent.suspended, иначе
 * приостановленный агент узнал бы о нём лишь по 403; EXCLUDED и неизвестный статус — никогда.
 */
export const pushAllowed = (status: AgentStatus | undefined, type: PaoEventType): boolean =>
  status === "ACTIVE" || (status === "SUSPENDED" && type === "agent.suspended");

function uuidV8(input: string): string {
  const b = createHash("sha256").update(input, "utf8").digest().subarray(0, 16);
  b[6] = (b[6]! & 0x0f) | 0x80; // версия 8
  b[8] = (b[8]! & 0x3f) | 0x80; // вариант RFC 9562
  const h = b.toString("hex");
  return `evt_${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * Ключ pg_advisory_xact_lock агента (РП39 п. 2): 64 бита SHA-256 со знаком, десятичной строкой (bigint без потерь).
 * Совпадение ключей двух агентов только ставит их запись в очередь, порядок номеров не ломает.
 */
export function eventSeqLockKey(agent_code: string): string {
  return createHash("sha256").update(`${EVENT_SEQ_LOCK_DOMAIN}\n${agent_code}`, "utf8").digest().readBigInt64BE(0).toString();
}

/** Событие ПАО из строки ленты: ни номера, ни записи журнала агенту не нужно. */
export const toPaoEvent = (e: StoredEvent): Event => ({ event_id: e.event_id, type: e.type, at: e.at, data: { ...e.data } });

/** Курсор after — не событие этого агента (чужое или неизвестное — одинаково, РП39 п. 7): 400 REQUEST_INVALID. */
export class EventCursorUnknown extends Error {
  constructor() {
    super("EVENT_CURSOR_UNKNOWN");
  }
}
