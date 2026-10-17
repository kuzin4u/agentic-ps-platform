// П2 Журнал согласий: записи мандата и статус как свёртка записей (PS-06 К1.2; A7 п. 4, 9; инварианты 5, 6).
import { createHash, randomBytes } from "node:crypto";
import { canonicalJson, sha256Hex, type JournalEntry } from "@kuzin4u/agentic-core";
import type { Mandate, MandateRequest } from "../shared/pao.js";

/**
 * Виды записей журнала согласий. Изменение мандата — только новой записью с parent_ref = id мандата (A7 п. 4.1).
 * MANDATE_REQUESTED пишет К1.3; подпись, отказ, отзыв и отказ агента — часть 2 PS-06.
 */
export const MANDATE_KINDS = [
  "MANDATE_REQUESTED",
  "MANDATE_SIGNED",
  "MANDATE_REJECTED",
  "MANDATE_REVOKED",
  "MANDATE_RELINQUISHED",
] as const;
export type MandateKind = (typeof MANDATE_KINDS)[number];

export type MandateStatus = NonNullable<Mandate["status"]>;

/** Предмет мандата — под обязательством, в журнале не раскрывается (A7 п. 9.2). */
export interface MandateSubject {
  readonly subject: string;
  readonly cart: MandateRequest["cart"] | null;
}

/**
 * Открытые реквизиты мандата в записи журнала: нужны ADP и verify (остаток, срок — A7 п. 9.2).
 * merchant_scope открыт осознанно: по нему ADP проверяет продавца (SPEC §5 п. 6, MANDATE_SCOPE).
 * principal_ref — только непрозрачный идентификатор клиента, не телефон, не ФИО, не номер карты (инвариант 1).
 */
export type MandateTerms = Omit<MandateRequest, "subject" | "cart"> & { readonly agent_code: string };

/** payload записи MANDATE_REQUESTED: открытые реквизиты и хэш-обязательство предмета. */
export type MandateRequestedPayload = MandateTerms & { readonly subject_commitment: string };

/** Метка области хэша id мандата (РП33 доп.): другая область — другой id при тех же агенте и ключе. */
export const MANDATE_ID_DOMAIN = "pao:mandate-id:v1";

/**
 * id мандата присваивает Платформа (РП33 доп.): `mnd_` + UUID версии 8 (RFC 9562 §5.8) из
 * SHA-256(`pao:mandate-id:v1\n` + agent_code + `\n` + SHA-256 от Idempotency-Key). Вычисляемый, а не случайный:
 * повтор того же запроса после сбоя находит записанный мандат, второй не пишется (`/audit` К1.3 № 2).
 * Сырой ключ агента в id не попадает — только его хэш, как в хранилище идемпотентности (РП30 доп.).
 */
export function mandateIdFor(agent_code: string, idempotencyKeyHash: string): string {
  if (agent_code === "" || agent_code.includes("\n")) throw new Error("mandateIdFor: agent_code");
  if (!/^[0-9a-f]{64}$/.test(idempotencyKeyHash)) throw new Error("mandateIdFor: хэш ключа — SHA-256 hex");
  const b = createHash("sha256")
    .update(`${MANDATE_ID_DOMAIN}\n${agent_code}\n${idempotencyKeyHash}`, "utf8")
    .digest()
    .subarray(0, 16);
  b[6] = (b[6]! & 0x0f) | 0x80; // версия 8
  b[8] = (b[8]! & 0x3f) | 0x80; // вариант RFC 9562
  const h = b.toString("hex");
  return `mnd_${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
/** Версии 4 (записанные до РП33 доп., случайные) и 8 (вычисляемые). */
export const MANDATE_ID = /^mnd_[0-9a-f]{8}-[0-9a-f]{4}-[48][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Цепочка журнала — одна на корневой мандат; CART с parent_id пишется в цепочку родителя. */
export const consentChain = (rootMandateId: string): string => `consent:${rootMandateId}`;

/** Соль обязательства — 32 случайных байта, base64url без дополнения (43 знака). */
export const newSalt = (): string => randomBytes(32).toString("base64url");

/** Хэш-обязательство предмета: sha256(canonicalJson({salt, subject, cart})), hex. */
export const subjectCommitment = (salt: string, s: MandateSubject): string =>
  sha256Hex(canonicalJson({ salt, subject: s.subject, cart: s.cart ?? null }));

/** Состояние мандата по записям не определяется: неизвестный вид записи, повтор, срок не читается (инвариант 3). */
export class ConsentStateUnknown extends Error {
  constructor(readonly mandateId: string, reason: string) {
    super(`CONSENT_STATE_UNKNOWN: ${mandateId}: ${reason}`);
  }
}

/**
 * Тот же Idempotency-Key — другой запрос (РП33 доп.): мандат по ключу записан или начат с другими реквизитами.
 * Бессрочно, и после срока хранения ключа в ядре: id вычисляется из ключа, второго мандата под ним не бывает.
 */
export class ConsentKeyReused extends Error {
  constructor(readonly mandateId: string) {
    super(`CONSENT_KEY_REUSED: ${mandateId}`);
  }
}

/** Цепочка не проходит проверку или предмет не совпадает с обязательством — мандат не отдаётся (инвариант 6). */
export class ConsentIntegrityError extends Error {
  constructor(readonly mandateId: string, reason: string) {
    super(`CONSENT_INTEGRITY: ${mandateId}: ${reason}`);
  }
}

const isKind = (k: string): k is MandateKind => (MANDATE_KINDS as readonly string[]).includes(k);

/** Метка времени RFC 3339 строго (`Date.parse` принимает и местные форматы — срок зависел бы от пояса процесса). */
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** Миллисекунды метки RFC 3339 или NaN. */
export const parseRfc3339 = (v: unknown): number => (typeof v === "string" && RFC3339.test(v) ? Date.parse(v) : Number.NaN);

/**
 * Статус мандата — свёртка его записей (запись мандата и записи с parent_ref = id) на момент now.
 * PENDING_SIGNATURE → ACTIVE (подписан) или REJECTED; ACTIVE или PENDING_SIGNATURE → REVOKED (отзыв клиентом или
 * отказ агента); не отозванный и не отклонённый с наступившим valid_to — EXPIRED (записи не нужно).
 * EXHAUSTED — из сервиса состояния (П3, PS-09), не из журнала. Неизвестный вид записи, вторая подпись, запись после
 * отзыва — ConsentStateUnknown: догадки нет (инвариант 3).
 */
export function deriveStatus(mandateId: string, entries: readonly JournalEntry[], now: Date): MandateStatus {
  const own = entries.filter((e) => e.ref === mandateId || e.parent_ref === mandateId);
  const head = own[0];
  if (!head || head.ref !== mandateId || head.kind !== "MANDATE_REQUESTED") {
    throw new ConsentStateUnknown(mandateId, "нет записи MANDATE_REQUESTED первой");
  }
  let status: MandateStatus = "PENDING_SIGNATURE";
  for (const e of own.slice(1)) {
    if (!isKind(e.kind)) throw new ConsentStateUnknown(mandateId, `вид записи ${e.kind}`);
    // Дочерний мандат (CART с parent_id) — своя запись MANDATE_REQUESTED, на статус родителя не влияет.
    // Повтор головной записи (ref = id) — не пропуск, а отказ.
    if (e.kind === "MANDATE_REQUESTED" && e.ref !== mandateId) continue;
    if (status === "PENDING_SIGNATURE" && (e.kind === "MANDATE_SIGNED" || e.kind === "MANDATE_REJECTED")) {
      status = e.kind === "MANDATE_SIGNED" ? "ACTIVE" : "REJECTED";
    } else if (
      (status === "PENDING_SIGNATURE" || status === "ACTIVE") &&
      (e.kind === "MANDATE_REVOKED" || e.kind === "MANDATE_RELINQUISHED")
    ) {
      status = "REVOKED";
    } else {
      throw new ConsentStateUnknown(mandateId, `${e.kind} при статусе ${status}`);
    }
  }
  if (status === "PENDING_SIGNATURE" || status === "ACTIVE") {
    const validTo = parseRfc3339((head.payload as MandateRequestedPayload).valid_to);
    if (Number.isNaN(validTo)) throw new ConsentStateUnknown(mandateId, "valid_to не читается");
    if (now.getTime() >= validTo) return "EXPIRED";
  }
  return status;
}

/**
 * Статус CART под INTENT — свёртка вместе со статусом родителя (РП35): собственные REVOKED и REJECTED сохраняются;
 * родитель REVOKED или REJECTED — CART REVOKED; родитель EXPIRED — CART EXPIRED; иначе — собственный статус.
 * Записей потомкам нет: отзыв родителя действует на CART с момента своей записи, в том числе на CART, записанный
 * в цепочку позже отзыва по гонке «проверка родителя → запись CART». Одно вычисление для GET, verify, подписи и ADP.
 * Ветки «родитель EXPIRED» и «родитель REJECTED» сейчас недостижимы (срок CART не позже родителя — assertNarrows;
 * CART пишется только под ACTIVE) и оставлены защитой на случай смены этих правил.
 */
export function withParentStatus(own: MandateStatus, parent: MandateStatus): MandateStatus {
  if (own === "REVOKED" || own === "REJECTED") return own;
  if (parent === "REVOKED" || parent === "REJECTED") return "REVOKED";
  if (parent === "EXPIRED") return "EXPIRED";
  return own;
}
