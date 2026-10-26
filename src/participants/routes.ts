// П10 Шлюз участников, ПИ-8 (PROCESSING-INTERFACE §11): подпись мандата клиентом в приложении банка (РП12, РП36) и
// отзыв мандата клиентом (РП38). Неаутентифицированной точки нет, в том числе на стенде: каждое решение и каждый отзыв —
// запись участника с его подписью Ed25519 над хэшем мандата (РП36 п. 3–4). Подпись запроса по RFC 9421 и реестр участников — PS-20 (STATUS «Открыто»).
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { ConsentSignRejected, type ConsentJournal, type SignaturePolicy } from "../consent/journal.js";
import {
  ConsentIntegrityError,
  ConsentStateUnknown,
  MANDATE_ID,
  parseRfc3339,
  type MandateDecisionPayload,
  type MandateRevocationPayload,
  type PrincipalRevocationPayload,
} from "../consent/model.js";
import { isOpaquePrincipalRef } from "../consent/terms.js";
import type { Params } from "../shared/config.js";
import {
  CONFIRMATION_ID,
  newConfirmationRef,
  totalsHash,
  type ConfirmationDecision,
  type ConfirmationRecord,
  type ConfirmationStore,
} from "../confirm/index.js";
import type { StateService } from "../state/service.js";
import { limitsBody, type LimitsStore } from "./limits.js";
import { NOTIFICATION_ID, NotificationCursorUnknown, type ParticipantNotificationStore } from "./notifications.js";
import { agentStatusView, type MerchantApiDeps } from "./merchant-api.js";
import { isPaymentRef, maskRef, paymentMetadataBody, reconcile, type PaymentMetadataStore, type ReconcileDeps } from "./payments.js";
import { readinessBody, type ReadinessStore } from "./readiness.js";
import { ACQUIRER_ONLY, isMerchantId, type ParticipantRole, type TrustedParticipants } from "./trusted.js";
import type { ParticipantRequestVerifier } from "./verify.js";

export interface ParticipantDeps {
  readonly trusted: TrustedParticipants;
  readonly consent: ConsentJournal;
  readonly params: SignaturePolicy & Pick<Params, "unavailable_retry_after_sec"> & Partial<Pick<Params, "event_page_max">>;
  /** П3: счёт бюджета открывается после MANDATE_SIGNED (РП41 п. 3); без П3 или при сбое — первым резервом. */
  readonly state?: Pick<StateService, "open">;
  /** Лимиты клиента от банка (РП45 п. 1); без хранилища маршрута лимитов нет. */
  readonly limits?: LimitsStore;
  /** Часы Платформы для received_at записи лимитов. */
  readonly now?: () => Date;
  /** Подпись запроса участника у чтений ПИ-8 (RFC 9421, РП46 (в)); без неё маршрута GET лимитов нет. */
  readonly requests?: ParticipantRequestVerifier;
  /** Outbox участника (РП46 (б)); без него, без подписи запроса и без event_page_max маршрута ленты уведомлений нет. */
  readonly notifications?: ParticipantNotificationStore;
  /**
   * П6 (РП50 п. 4–5): решение человека по запросу подтверждения; без хранилища маршрута нет. skewSec — допуск часов
   * для decided_at (signature_skew_sec).
   */
  readonly confirmations?: { readonly store: Pick<ConfirmationStore, "get" | "decide" | "expire">; readonly skewSec: number };
  /**
   * Знак готовности продавца (РП57 п. 2–3): записи эквайрера; без хранилища маршрутов знака нет. skewSec — допуск часов
   * для issued_at (signature_skew_sec). GET — с подписью запроса участника роли ACQUIRER (requests).
   */
  readonly readiness?: { readonly store: Pick<ReadinessStore, "putAcquirer" | "current">; readonly skewSec: number };
  /**
   * Метаданные пакета и сверка credential_ref → op_ref (РП57 п. 5): без них маршрутов …/payments нет. Сверка — по записи
   * реквизита П5: в рабочем сервере П5 не подключено (токен-сервис оператора, ПИ-4), поэтому маршруты — только стенд и тесты.
   */
  readonly payments?: { readonly store: PaymentMetadataStore; readonly reconcile: ReconcileDeps; readonly skewSec: number };
  /** Статус агента для эквайрера (РП57 п. 6): реестр и контур сервера; без них маршрута нет. */
  readonly agentStatus?: Pick<MerchantApiDeps, "registry" | "contour">;
}

/** Коды ответа ПИ-8 подписи (processing-interface.yaml); тело ошибки — `{code}`, причина — в журнале процесса. */
const HTTP: Readonly<Record<string, number>> = {
  REQUEST_INVALID: 400,
  SIGNATURE_INVALID: 401,
  MANDATE_NOT_FOUND: 404,
  MANDATE_HASH_MISMATCH: 409,
  MANDATE_NOT_PENDING: 409,
  LIMITS_VERSION_CONFLICT: 409,
  LIMITS_NOT_FOUND: 404,
  LIMITS_UNSUPPORTED: 422,
  CONFIRMATION_NOT_FOUND: 404,
  CONFIRMATION_TOTALS_MISMATCH: 409,
  CONFIRMATION_NOT_PENDING: 409,
  QUALIFIED_SIGNATURE_REQUIRED: 422,
  MERCHANT_NOT_SERVED: 403,
  MERCHANT_NOT_FOUND: 404,
  READINESS_CONFLICT: 409,
  READINESS_SUSPENDED: 409,
  CREDENTIAL_NOT_FOUND: 404,
  METADATA_CONFLICT: 409,
  AGENT_UNKNOWN: 404,
  STATE_UNAVAILABLE: 503,
  UPSTREAM_UNAVAILABLE: 503,
};

const DECISIONS = ["SIGN", "REJECT"] as const;
const SIGNATURE_TYPES = ["simple", "qualified", "gov_id"] as const;
const SIGN_FIELDS = [
  "decision",
  "kid",
  "mandate_hash",
  "participant_code",
  "signature",
  "signature_ref",
  "signature_type",
  "signed_at",
  "token_consent",
].join(",");

/**
 * Ссылки банка signature_ref и revocation_ref уходят агенту в выписке (РП38 п. 7): только непрозрачная ссылка — маска
 * principal_ref (без `@`, `+`, пробела и семи цифр подряд: не проходят СНИЛС, ЕСИА, телефон). ПДн в них банк не кладёт (ПИ-8).
 */
const isOpaqueRef = isOpaquePrincipalRef;

/** Тело подписи: ровно поля записи и подпись (лишнее поле не подписано — отказ, а не пропуск). */
function signBody(mandate_id: string, v: unknown): MandateDecisionPayload | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== SIGN_FIELDS) return undefined;
  const str = (k: string, max = 256) => typeof o[k] === "string" && (o[k] as string).length > 0 && (o[k] as string).length <= max;
  if (!["participant_code", "kid", "mandate_hash", "signature_ref", "signature", "signed_at"].every((k) => str(k))) return undefined;
  if (!(DECISIONS as readonly unknown[]).includes(o.decision)) return undefined;
  if (!(SIGNATURE_TYPES as readonly unknown[]).includes(o.signature_type)) return undefined;
  if (typeof o.token_consent !== "boolean" || Number.isNaN(parseRfc3339(o.signed_at))) return undefined;
  if (!/^[0-9a-f]{64}$/.test(o.mandate_hash as string) || !isOpaqueRef(o.signature_ref)) return undefined;
  return {
    participant_code: o.participant_code as string,
    kid: o.kid as string,
    mandate_id,
    mandate_hash: o.mandate_hash as string,
    decision: o.decision as MandateDecisionPayload["decision"],
    signature_type: o.signature_type as MandateDecisionPayload["signature_type"],
    signature_ref: o.signature_ref as string,
    token_consent: o.token_consent,
    signed_at: o.signed_at as string,
    signature: o.signature as string,
  };
}

const REVOKE_FIELDS = ["kid", "mandate_hash", "participant_code", "revocation_ref", "revoked_at", "signature"].join(",");

/** Тело отзыва: ровно поля записи и подпись (РП38 п. 1). */
function revokeBody(mandate_id: string, v: unknown): MandateRevocationPayload | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== REVOKE_FIELDS) return undefined;
  const str = (k: string) => typeof o[k] === "string" && (o[k] as string).length > 0 && (o[k] as string).length <= 256;
  if (!["participant_code", "kid", "mandate_hash", "revocation_ref", "revoked_at", "signature"].every(str)) return undefined;
  if (Number.isNaN(parseRfc3339(o.revoked_at)) || !/^[0-9a-f]{64}$/.test(o.mandate_hash as string)) return undefined;
  if (!isOpaqueRef(o.revocation_ref)) return undefined;
  return {
    participant_code: o.participant_code as string,
    kid: o.kid as string,
    mandate_id,
    mandate_hash: o.mandate_hash as string,
    revocation_ref: o.revocation_ref as string,
    revoked_at: o.revoked_at as string,
    signature: o.signature as string,
  };
}

const REVOKE_ALL_FIELDS = ["kid", "participant_code", "revocation_ref", "revoked_at", "signature"].join(",");

/** Тело revoke-all: ровно поля записи без principal_ref (он в пути) и подпись (РП45 п. 4). */
function revokeAllBody(principal_ref: string, v: unknown): PrincipalRevocationPayload | undefined {
  if (!isOpaqueRef(principal_ref) || typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== REVOKE_ALL_FIELDS) return undefined;
  const str = (k: string) => typeof o[k] === "string" && (o[k] as string).length > 0 && (o[k] as string).length <= 256;
  if (!["participant_code", "kid", "revocation_ref", "revoked_at", "signature"].every(str)) return undefined;
  if (Number.isNaN(parseRfc3339(o.revoked_at)) || !isOpaqueRef(o.revocation_ref)) return undefined;
  return {
    participant_code: o.participant_code as string,
    kid: o.kid as string,
    principal_ref,
    revocation_ref: o.revocation_ref as string,
    revoked_at: o.revoked_at as string,
    signature: o.signature as string,
  };
}

export async function participantRoutes(app: FastifyInstance, deps: ParticipantDeps): Promise<void> {
  // Неразборный JSON и иные отказы Fastify до обработчика — тело ПИ-8 `{code}`, а не тело Fastify (как в ПАО).
  app.setErrorHandler((err: { statusCode?: number }, _req, reply) => {
    const http = err.statusCode ?? 500;
    if (http === 413) return reply.code(413).send({ code: "REQUEST_INVALID" });
    if (http >= 400 && http < 500) return reply.code(400).send({ code: "REQUEST_INVALID" });
    return reply.code(503).header("retry-after", String(deps.params.unavailable_retry_after_sec)).send({ code: "UPSTREAM_UNAVAILABLE" });
  });
  /** Запись участника по мандату: тело → журнал → `{mandate_id, status}`; отказы — `{code}`, причина — в журнал процесса. */
  async function participantWrite<D extends { participant_code: string }>(
    req: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
    parse: (id: string, v: unknown) => D | undefined,
    write: (d: D) => Promise<{ id: string; status: string; replayed: boolean }>,
    log: { done: string; replayed: string; rejected: string },
  ): Promise<FastifyReply> {
    const fail = (code: keyof typeof HTTP) => {
      const http = HTTP[code]!;
      if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
      return reply.code(http).send({ code });
    };
    const id = req.params.id;
    const d = MANDATE_ID.test(id) ? parse(id, req.body) : undefined;
    if (!d) return fail("REQUEST_INVALID");
    try {
      const r = await write(d);
      req.log.info({ participant_code: d.participant_code, mandate_id: id, status: r.status }, r.replayed ? log.replayed : log.done);
      return reply.code(200).send({ mandate_id: r.id, status: r.status });
    } catch (err) {
      if (err instanceof ConsentSignRejected) {
        req.log.info({ participant_code: d.participant_code, mandate_id: id, reason: err.reason, status: err.status }, log.rejected);
        return fail(err.reason);
      }
      if (err instanceof ConsentIntegrityError || err instanceof ConsentStateUnknown) {
        req.log.error({ err, mandate_id: id }, "ПИ-8: журнал согласий — состояние не подтверждено");
        return fail("STATE_UNAVAILABLE");
      }
      req.log.error({ err, mandate_id: id }, "ПИ-8: сбой журнала согласий");
      return fail("UPSTREAM_UNAVAILABLE");
    }
  }

  app.post<{ Params: { id: string } }>("/participants/v1/mandates/:id/sign", async (req, reply) =>
    participantWrite(
      req,
      reply,
      signBody,
      async (d) => {
        const { signature, ...record } = d;
        const r = await deps.consent.sign(d, () => deps.trusted.verify(d.participant_code, d.kid, record, signature), deps.params);
        // Открытие идемпотентно и не бросает: сбой ответ банку не меняет, счёт откроет первый резерв (РП41 п. 3).
        if (r.status === "ACTIVE") await deps.state?.open(r.id);
        return r;
      },
      {
        done: "ПИ-8: решение клиента записано",
        replayed: "ПИ-8: повтор той же подписи — решение уже записано, записи нет",
        rejected: "ПИ-8: решение не записано",
      },
    ),
  );

  // Отзыв клиентом (РП38 п. 1, 4): своя метка подписи; полномочий уже нет — текущий статус без записи.
  app.post<{ Params: { id: string } }>("/participants/v1/mandates/:id/revoke", async (req, reply) =>
    participantWrite(
      req,
      reply,
      revokeBody,
      (d) => {
        const { signature, ...record } = d;
        return deps.consent.revoke(d, () => deps.trusted.verifyRevocation(record, signature));
      },
      {
        done: "ПИ-8: отзыв клиентом записан",
        replayed: "ПИ-8: отзыв — полномочий уже нет, записи нет",
        rejected: "ПИ-8: отзыв не записан",
      },
    ),
  );

  // Отзыв всех полномочий клиента одним действием (РП45 п. 4, РП46 (а)): тело → подпись банка (401 до хранилища) → метка
  // пары по порядку фиксации → MANDATE_REVOKED и mandate.revoked каждому ACTIVE-мандату пары, подписанному до метки.
  // 200 — после всех записей; сбой посередине — 503, банк повторяет тот же revocation_ref.
  app.post<{ Params: { ref: string } }>("/participants/v1/principals/:ref/revoke-all", async (req, reply) => {
    const fail = (code: keyof typeof HTTP) => {
      const http = HTTP[code]!;
      if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
      return reply.code(http).send({ code });
    };
    const d = revokeAllBody(req.params.ref, req.body);
    if (!d) return fail("REQUEST_INVALID");
    const fields = { participant_code: d.participant_code, principal_ref: d.principal_ref, revocation_ref: d.revocation_ref };
    try {
      const r = await deps.consent.revokeAll(d, ({ signature, ...record }) => deps.trusted.verifyPrincipalRevocation(record, signature));
      req.log.info({ ...fields, revoked: r.revoked }, r.replayed ? "ПИ-8: revoke-all — тот же revocation_ref с другой записью, метка прежняя" : "ПИ-8: revoke-all записан");
      return reply.code(200).send({ principal_ref: r.principal_ref, revocation_ref: r.revocation_ref, revoked: r.revoked });
    } catch (err) {
      if (err instanceof ConsentSignRejected) {
        req.log.info({ ...fields, reason: err.reason }, "ПИ-8: revoke-all не записан");
        return fail(err.reason);
      }
      if (err instanceof ConsentIntegrityError || err instanceof ConsentStateUnknown) {
        req.log.error({ err, ...fields }, "ПИ-8: revoke-all — состояние мандата не подтверждено");
        return fail("STATE_UNAVAILABLE");
      }
      req.log.error({ err, ...fields }, "ПИ-8: revoke-all — сбой журнала согласий");
      return fail("UPSTREAM_UNAVAILABLE");
    }
  });

  // Лента уведомлений клиента через банк (РП46 (б) п. 3): подпись запроса участника (RFC 9421) → только свои, участник —
  // из проверенной подписи; after — notification_id этого участника, чужой, неизвестный или не по форме — 400 (как лента
  // агента, РП39 п. 7, доп. п. 4). Страница — не больше event_page_max, по возрастанию seq.
  const notifications = deps.notifications;
  const pageMax = deps.params.event_page_max;
  if (deps.requests && notifications && pageMax !== undefined) {
    const requests = deps.requests;
    app.get("/participants/v1/notifications", async (req, reply) => {
      const fail = (code: keyof typeof HTTP) => {
        const http = HTTP[code]!;
        if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
        return reply.code(http).send({ code });
      };
      const auth = await verifyRead(requests, req);
      if (!auth.ok) {
        if (auth.code === "UPSTREAM_UNAVAILABLE") {
          req.log.error({ err: auth.cause }, "ПИ-8: лента уведомлений — сбой хранилища nonce");
          return fail("UPSTREAM_UNAVAILABLE");
        }
        req.log.info("ПИ-8: лента уведомлений — подпись запроса участника не проверена");
        return fail("SIGNATURE_INVALID");
      }
      const query = req.query as Record<string, unknown>;
      const keys = Object.keys(query);
      const after = query.after;
      if (keys.some((k) => k !== "after") || (after !== undefined && (typeof after !== "string" || !NOTIFICATION_ID.test(after)))) {
        return fail("REQUEST_INVALID");
      }
      try {
        const page = await notifications.page(auth.participant_code, after, pageMax);
        return reply.code(200).send({
          notifications: page.map((n) => ({ notification_id: n.notification_id, seq: n.seq, type: n.type, at: n.at, data: n.data })),
        });
      } catch (err) {
        if (err instanceof NotificationCursorUnknown) return fail("REQUEST_INVALID");
        req.log.error({ err, participant_code: auth.participant_code }, "ПИ-8: сбой ленты уведомлений");
        return fail("UPSTREAM_UNAVAILABLE");
      }
    });
  }

  // Решение человека по запросу подтверждения (ПИ-8, РП50 п. 4–5; Дополнения п. 3): тело → подпись банка или UPK (401 до
  // хранилища) → UPK без instrument_chosen (400 — после подписи: роль без проверенной подписи не раскрывается, РП51 п. 13) → запрос (404) → банк клиента корневого INTENT или UPK (401, РП51 п. 12) → decided_at не в будущем сверх допуска (401) →
  // повтор той же записи (200) → totals_hash (409) → срок и статус (409) → условная запись. Ссылка — при APPROVE.
  const confirmations = deps.confirmations;
  if (confirmations) {
    app.post<{ Params: { id: string } }>("/participants/v1/confirmations/:id", async (req, reply) => {
      const fail = (code: keyof typeof HTTP, extra: Record<string, unknown> = {}) => {
        const http = HTTP[code]!;
        if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
        return reply.code(http).send({ code, ...extra });
      };
      const id = req.params.id;
      const d = CONFIRMATION_ID.test(id) ? confirmBody(req.body) : undefined;
      if (!d) return fail("REQUEST_INVALID");
      const { signature, ...record } = d;
      if (!deps.trusted.verifyConfirmation({ ...record, confirmation_id: id }, signature)) {
        req.log.info({ participant_code: d.participant_code, confirmation_id: id }, "ПИ-8: подпись решения по подтверждению не проверена");
        return fail("SIGNATURE_INVALID");
      }
      // Роль — из списка доверенных, снимком до первого await (Р-205): оператор УПК решает по любому запросу (РП51 п. 12).
      const upk = deps.trusted.role(d.participant_code) === "UPK";
      // Страница УПК без выбора инструмента — не по форме (РП51 п. 13): от банка поле по желанию.
      if (upk && d.instrument_chosen === undefined) {
        req.log.info({ participant_code: d.participant_code, confirmation_id: id }, "ПИ-8: решение UPK без instrument_chosen");
        return fail("REQUEST_INVALID");
      }
      const now = (deps.now ?? (() => new Date()))();
      const at = now.toISOString();
      let r: ConfirmationRecord | undefined;
      let bank: string | null | undefined;
      try {
        r = await confirmations.store.get(id);
        if (!r) return fail("CONFIRMATION_NOT_FOUND");
        // Банк клиента — из журнала (подпись корня), а не со слов участника (инвариант 5, РП45).
        const m = await deps.consent.adpMandate(r.mandate_id, r.agent_code);
        bank = m ? (m.client?.participant_code ?? null) : undefined;
      } catch (err) {
        req.log.error({ err, confirmation_id: id }, "ПИ-8: запрос подтверждения или мандат не прочитаны");
        return fail("STATE_UNAVAILABLE");
      }
      if (bank === undefined) {
        // Запрос есть, мандата нет — порча записей Платформы, а не ошибка банка.
        req.log.error({ confirmation_id: id, incident: true }, "ПИ-8: мандат запроса подтверждения не найден");
        return fail("STATE_UNAVAILABLE");
      }
      if (!upk && bank !== d.participant_code) {
        req.log.info({ participant_code: d.participant_code, confirmation_id: id }, "ПИ-8: решение по подтверждению — не банк клиента");
        return fail("SIGNATURE_INVALID");
      }
      const decided = parseRfc3339(d.decided_at);
      if (decided > now.getTime() + confirmations.skewSec * 1000) {
        req.log.info({ participant_code: d.participant_code, confirmation_id: id }, "ПИ-8: decided_at в будущем сверх допуска часов");
        return fail("SIGNATURE_INVALID");
      }
      if (r.decision && sameDecision(r.decision, d)) return reply.code(200).send(confirmationView(r));
      if (d.totals_hash !== totalsHash(r)) {
        req.log.info({ participant_code: d.participant_code, confirmation_id: id }, "ПИ-8: totals_hash не совпадает с запросом");
        return fail("CONFIRMATION_TOTALS_MISMATCH");
      }
      if (r.status !== "PENDING") return fail("CONFIRMATION_NOT_PENDING", { status: r.status });
      try {
        // Срок (РП50 п. 5, Дополнения п. 3): решение — не позже expires_at, запись — строго раньше него.
        if (!(decided <= Date.parse(r.expires_at)) || !(at < r.expires_at)) {
          await confirmations.store.expire(id, at);
          return fail("CONFIRMATION_NOT_PENDING", { status: "EXPIRED" });
        }
        const done = await confirmations.store.decide(id, d, d.decision === "APPROVE" ? newConfirmationRef() : null, at);
        if (done) {
          req.log.info({ participant_code: d.participant_code, confirmation_id: id, status: done.status }, "ПИ-8: решение по подтверждению записано");
          return reply.code(200).send(confirmationView(done));
        }
        // Другой экземпляр записал решение или срок вышел между чтением и записью.
        const cur = await confirmations.store.get(id);
        if (cur?.decision && sameDecision(cur.decision, d)) return reply.code(200).send(confirmationView(cur));
        return fail("CONFIRMATION_NOT_PENDING", { status: cur?.status ?? "EXPIRED" });
      } catch (err) {
        req.log.error({ err, confirmation_id: id }, "ПИ-8: решение по подтверждению не записано");
        return fail("STATE_UNAVAILABLE");
      }
    });
  }

  // Знак готовности продавца (ПИ-8 «Эквайрер», РП57 п. 2): тело → подпись эквайрера (401 до хранилища; роль без
  // проверенной подписи не раскрывается) → issued_at не в будущем сверх допуска (401) → продавец из перечня (403) →
  // только вставка: повтор той же записи — 200 без записи, та же ссылка с другой записью — 409, приостановлено — 409.
  const readiness = deps.readiness;
  if (readiness) {
    app.post<{ Params: { id: string } }>("/participants/v1/merchants/:id/readiness", async (req, reply) => {
      const fail = (code: keyof typeof HTTP) => {
        const http = HTTP[code]!;
        if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
        return reply.code(http).send({ code });
      };
      const merchant_id = req.params.id;
      const b = readinessBody(merchant_id, req.body);
      if (!b) return fail("REQUEST_INVALID");
      const { record, signature } = b;
      const fields = { participant_code: record.participant_code, merchant_id, readiness_ref: record.readiness_ref, status: record.status };
      if (!deps.trusted.verifyReadiness(record, signature)) {
        req.log.info(fields, "ПИ-8: знак готовности — подпись эквайрера не проверена");
        return fail("SIGNATURE_INVALID");
      }
      const now = (deps.now ?? (() => new Date()))();
      if (parseRfc3339(record.issued_at) > now.getTime() + readiness.skewSec * 1000) {
        req.log.info(fields, "ПИ-8: знак готовности — issued_at в будущем сверх допуска часов");
        return fail("SIGNATURE_INVALID");
      }
      // Намеренно 403, а не 404 (РП57 п. 3): эквайрер ошибся в своём перечне; на GET чужой продавец — 404.
      if (!deps.trusted.serves(record.participant_code, merchant_id)) {
        req.log.info(fields, "ПИ-8: знак готовности — продавца нет в перечне эквайрера");
        return fail("MERCHANT_NOT_SERVED");
      }
      try {
        const put = await readiness.store.putAcquirer({ ...record, signature, received_at: now.toISOString() });
        if (put === "conflict") {
          req.log.info(fields, "ПИ-8: знак готовности — тот же readiness_ref с другой записью");
          return fail("READINESS_CONFLICT");
        }
        if (put === "suspended") {
          req.log.info(fields, "ПИ-8: знак готовности приостановлен оператором — запись эквайрера не принята");
          return fail("READINESS_SUSPENDED");
        }
        const view = await readiness.store.current(merchant_id);
        req.log.info({ ...fields, put, current: view.status }, put === "replayed" ? "ПИ-8: повтор записи знака — записи нет" : "ПИ-8: запись знака готовности принята");
        return reply.code(200).send({ merchant_id: view.merchant_id, status: view.status, since: view.since });
      } catch (err) {
        req.log.error({ err, ...fields }, "ПИ-8: сбой хранилища знака готовности");
        return fail("STATE_UNAVAILABLE");
      }
    });

    const requests = deps.requests;
    if (requests) {
      // Статус знака своего продавца с причиной приостановления (РП57 п. 3): подпись запроса участника роли ACQUIRER;
      // чужой продавец — 404, как нет записи (чужие перечни не раскрываются).
      app.get<{ Params: { id: string } }>("/participants/v1/merchants/:id/readiness", async (req, reply) => {
        const fail = (code: keyof typeof HTTP) => {
          const http = HTTP[code]!;
          if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
          return reply.code(http).send({ code });
        };
        const auth = await verifyRead(requests, req, ACQUIRER_ONLY);
        if (!auth.ok) {
          if (auth.code === "UPSTREAM_UNAVAILABLE") {
            req.log.error({ err: auth.cause }, "ПИ-8: GET знака — сбой хранилища nonce");
            return fail("UPSTREAM_UNAVAILABLE");
          }
          req.log.info("ПИ-8: GET знака — подпись запроса эквайрера не проверена");
          return fail("SIGNATURE_INVALID");
        }
        const merchant_id = req.params.id;
        if (!isMerchantId(merchant_id)) return fail("REQUEST_INVALID");
        if (!deps.trusted.serves(auth.participant_code, merchant_id)) return fail("MERCHANT_NOT_FOUND");
        try {
          return reply.code(200).send(await readiness.store.current(merchant_id));
        } catch (err) {
          req.log.error({ err, participant_code: auth.participant_code, merchant_id }, "ПИ-8: сбой хранилища знака готовности");
          return fail("STATE_UNAVAILABLE");
        }
      });
    }
  }

  // Метаданные пакета и сверка (ПИ-8 «Эквайрер», РП57 п. 5): тело → подпись эквайрера (401) → submitted_at не в будущем
  // сверх допуска (401) → продавец из перечня (403) → реквизит этого продавца (404, без записи) → только вставка (повтор —
  // 200, та же ссылка с другой записью — 409) → сверка по записи реквизита на момент ответа. ADP метаданные не читает.
  const payments = deps.payments;
  if (payments) {
    app.post<{ Params: { id: string } }>("/participants/v1/merchants/:id/payments", async (req, reply) => {
      const fail = (code: keyof typeof HTTP) => {
        const http = HTTP[code]!;
        if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
        return reply.code(http).send({ code });
      };
      const merchant_id = req.params.id;
      const b = paymentMetadataBody(merchant_id, req.body);
      if (!b) return fail("REQUEST_INVALID");
      const { record, signature } = b;
      // В журнал процесса — маска credential_ref, без тела записи (РП57 доп. 5 (г)).
      const fields = { participant_code: record.participant_code, merchant_id, metadata_ref: record.metadata_ref, credential_ref: maskRef(record.credential_ref) };
      if (!deps.trusted.verifyPaymentMetadata(record, signature)) {
        req.log.info(fields, "ПИ-8: метаданные пакета — подпись эквайрера не проверена");
        return fail("SIGNATURE_INVALID");
      }
      const now = (deps.now ?? (() => new Date()))();
      if (parseRfc3339(record.submitted_at) > now.getTime() + payments.skewSec * 1000) {
        req.log.info(fields, "ПИ-8: метаданные пакета — submitted_at в будущем сверх допуска часов");
        return fail("SIGNATURE_INVALID");
      }
      if (!deps.trusted.serves(record.participant_code, merchant_id)) {
        req.log.info(fields, "ПИ-8: метаданные пакета — продавца нет в перечне эквайрера");
        return fail("MERCHANT_NOT_SERVED");
      }
      try {
        // Реквизит другого продавца — как неизвестный (РП57 п. 5); метаданные по нему не пишутся.
        const before = await reconcile(payments.reconcile, record);
        if (!before) {
          // Попытка — в журнал процесса (РП57 доп. 5 (г)): кто, по какому продавцу, маска ссылки; в сверку не пишется.
          req.log.warn(fields, "ПИ-8: метаданные пакета по неизвестному реквизиту или реквизиту другого продавца — не записаны");
          return fail("CREDENTIAL_NOT_FOUND");
        }
        const put = await payments.store.put({ ...record, signature, received_at: now.toISOString() });
        if (put === "conflict") {
          req.log.info(fields, "ПИ-8: метаданные пакета — тот же metadata_ref с другой записью");
          return fail("METADATA_CONFLICT");
        }
        if (before.result === "MISMATCH") {
          // Вход для решения оператора о знаке (РП57 п. 2): автоматического приостановления нет.
          req.log.warn({ ...fields, mismatch: before.fields }, "ПИ-8: метаданные пакета расходятся с записью реквизита");
        }
        req.log.info({ ...fields, put, result: before.result }, put === "replayed" ? "ПИ-8: повтор метаданных — записи нет" : "ПИ-8: метаданные пакета приняты");
        return reply.code(200).send(before);
      } catch (err) {
        req.log.error({ err, ...fields }, "ПИ-8: сверка метаданных — хранилище недоступно");
        return fail("STATE_UNAVAILABLE");
      }
    });

    const requests = deps.requests;
    if (requests) {
      // Сверка по реквизиту (РП57 п. 5): последняя запись метаданных; чужой продавец, нет записи или реквизита — 404.
      app.get<{ Params: { id: string; credential_ref: string } }>("/participants/v1/merchants/:id/payments/:credential_ref", async (req, reply) => {
        const fail = (code: keyof typeof HTTP) => {
          const http = HTTP[code]!;
          if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
          return reply.code(http).send({ code });
        };
        const auth = await verifyRead(requests, req, ACQUIRER_ONLY);
        if (!auth.ok) {
          if (auth.code === "UPSTREAM_UNAVAILABLE") {
            req.log.error({ err: auth.cause }, "ПИ-8: GET сверки — сбой хранилища nonce");
            return fail("UPSTREAM_UNAVAILABLE");
          }
          return fail("SIGNATURE_INVALID");
        }
        const { id: merchant_id, credential_ref } = req.params;
        if (!isMerchantId(merchant_id) || !isPaymentRef(credential_ref)) return fail("REQUEST_INVALID");
        if (!deps.trusted.serves(auth.participant_code, merchant_id)) return fail("CREDENTIAL_NOT_FOUND");
        try {
          const last = await payments.store.latest(merchant_id, credential_ref);
          const r = last && (await reconcile(payments.reconcile, last));
          if (!r) return fail("CREDENTIAL_NOT_FOUND");
          return reply.code(200).send(r);
        } catch (err) {
          req.log.error({ err, merchant_id, credential_ref: maskRef(credential_ref) }, "ПИ-8: сверка метаданных — хранилище недоступно");
          return fail("STATE_UNAVAILABLE");
        }
      });
    }
  }

  // Статус агента для эквайрера (ПИ-8, РП57 п. 6): подпись запроса роли ACQUIRER; тело и коды — как у API продавцов.
  const agentStatus = deps.agentStatus;
  if (agentStatus && deps.requests) {
    const requests = deps.requests;
    app.get<{ Params: { code: string } }>("/participants/v1/agents/:code/status", async (req, reply) => {
      const fail = (code: keyof typeof HTTP) => {
        const http = HTTP[code]!;
        if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
        return reply.code(http).send({ code });
      };
      const auth = await verifyRead(requests, req, ACQUIRER_ONLY);
      if (!auth.ok) {
        if (auth.code === "UPSTREAM_UNAVAILABLE") {
          req.log.error({ err: auth.cause }, "ПИ-8: статус агента — сбой хранилища nonce");
          return fail("UPSTREAM_UNAVAILABLE");
        }
        return fail("SIGNATURE_INVALID");
      }
      let view: Awaited<ReturnType<typeof agentStatusView>>;
      try {
        view = await agentStatusView(agentStatus, req.params.code);
      } catch (err) {
        req.log.error({ err }, "ПИ-8: статус агента — реестр недоступен");
        return fail("UPSTREAM_UNAVAILABLE");
      }
      return view ? reply.code(200).send(view) : fail("AGENT_UNKNOWN");
    });
  }

  const limits = deps.limits;
  if (!limits) return;
  // Лимиты клиента (РП45 п. 1, 3): тело → подпись банка (401 до хранилища) → только вставка с версией. GET того же пути —
  // с подписью запроса участника (RFC 9421, PS-20 часть 2): без неё лимиты клиента отдавались бы любому.
  app.put<{ Params: { ref: string } }>("/participants/v1/principals/:ref/limits", async (req, reply) => {
    const fail = (code: keyof typeof HTTP) => {
      const http = HTTP[code]!;
      if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
      return reply.code(http).send({ code });
    };
    const b = limitsBody(req.params.ref, req.body);
    if (!b.ok) return fail(b.code);
    const { record, signature } = b;
    if (!deps.trusted.verifyLimits(record, signature)) {
      req.log.info({ participant_code: record.participant_code }, "ПИ-8: лимиты не записаны — подпись не проверена");
      return fail("SIGNATURE_INVALID");
    }
    try {
      const put = await limits.put({ ...record, signature, received_at: (deps.now ?? (() => new Date()))().toISOString() });
      const fields = { participant_code: record.participant_code, principal_ref: record.principal_ref, version: record.version, put };
      if (put === "conflict") {
        req.log.info(fields, "ПИ-8: лимиты не записаны — версия не выше действующей или другая запись той же версии");
        return fail("LIMITS_VERSION_CONFLICT");
      }
      req.log.info(fields, put === "replayed" ? "ПИ-8: повтор записи лимитов — записи нет" : "ПИ-8: лимиты клиента записаны");
      return reply.code(200).send({ principal_ref: record.principal_ref, version: record.version });
    } catch (err) {
      req.log.error({ err, participant_code: record.participant_code }, "ПИ-8: сбой хранилища лимитов");
      return fail("UPSTREAM_UNAVAILABLE");
    }
  });

  const requests = deps.requests;
  if (!requests) return;
  // Чтение действующей записи лимитов (РП46 (в)): подпись запроса участника (RFC 9421) → только своя пара — участник из
  // проверенной подписи; пара другого банка — 404, как нет записи (не раскрываем, что клиент есть у другого банка).
  app.get<{ Params: { ref: string } }>("/participants/v1/principals/:ref/limits", async (req, reply) => {
    const fail = (code: keyof typeof HTTP) => {
      const http = HTTP[code]!;
      if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
      return reply.code(http).send({ code });
    };
    const auth = await verifyRead(requests, req);
    if (!auth.ok) {
      if (auth.code === "UPSTREAM_UNAVAILABLE") {
        req.log.error({ err: auth.cause }, "ПИ-8: GET лимитов — сбой хранилища nonce");
        return fail("UPSTREAM_UNAVAILABLE");
      }
      req.log.info("ПИ-8: GET лимитов — подпись запроса участника не проверена");
      return fail("SIGNATURE_INVALID");
    }
    if (!isOpaqueRef(req.params.ref)) return fail("REQUEST_INVALID");
    try {
      const cur = await limits.current({ participant_code: auth.participant_code, principal_ref: req.params.ref });
      if (!cur) return fail("LIMITS_NOT_FOUND");
      return reply.code(200).send(cur);
    } catch (err) {
      req.log.error({ err, participant_code: auth.participant_code }, "ПИ-8: сбой хранилища лимитов");
      return fail("UPSTREAM_UNAVAILABLE");
    }
  });
}

const CONFIRM_FIELDS = ["decided_at", "decision", "kid", "participant_code", "signature", "totals_hash"].join(",");
/** То же с выбором инструмента на странице УПК (РП51 п. 13). */
const CONFIRM_FIELDS_INSTRUMENT = ["decided_at", "decision", "instrument_chosen", "kid", "participant_code", "signature", "totals_hash"].join(",");

/** Тело решения по запросу подтверждения (РП50 п. 4): ровно поля записи и подпись; разбор — новый объект (снимок, Р-205). */
function confirmBody(v: unknown): ConfirmationDecision | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  const fields = Object.keys(o).sort().join(",");
  if (fields !== CONFIRM_FIELDS && fields !== CONFIRM_FIELDS_INSTRUMENT) return undefined;
  if (o.instrument_chosen !== undefined && o.instrument_chosen !== "CARD" && o.instrument_chosen !== "SBP") return undefined;
  const str = (k: string) => typeof o[k] === "string" && (o[k] as string).length > 0 && (o[k] as string).length <= 256;
  if (!["participant_code", "kid", "decided_at", "signature"].every(str)) return undefined;
  if (o.decision !== "APPROVE" && o.decision !== "REJECT") return undefined;
  if (typeof o.totals_hash !== "string" || !/^[0-9a-f]{64}$/.test(o.totals_hash)) return undefined;
  if (!/^[A-Za-z0-9_-]{86}$/.test(o.signature as string) || Number.isNaN(parseRfc3339(o.decided_at))) return undefined;
  return {
    participant_code: o.participant_code as string,
    kid: o.kid as string,
    decision: o.decision,
    totals_hash: o.totals_hash,
    decided_at: o.decided_at as string,
    signature: o.signature as string,
    ...(o.instrument_chosen === undefined ? {} : { instrument_chosen: o.instrument_chosen }),
  };
}

const sameDecision = (a: ConfirmationDecision, b: ConfirmationDecision): boolean =>
  a.participant_code === b.participant_code &&
  a.kid === b.kid &&
  a.decision === b.decision &&
  a.totals_hash === b.totals_hash &&
  a.decided_at === b.decided_at &&
  a.signature === b.signature &&
  a.instrument_chosen === b.instrument_chosen;

/** Ответ 200 ПИ-8: ссылка — только у одобренного, ещё не погашенного (РП50 п. 6, ответ ПИ-8). */
const confirmationView = (r: ConfirmationRecord) => ({
  confirmation_id: r.confirmation_id,
  status: r.status,
  ...(r.status === "APPROVED" && r.confirmation_ref ? { confirmation_ref: r.confirmation_ref } : {}),
});

/**
 * Подпись запроса участника у чтения ПИ-8 (РП46 (в)): путь и запрос — как пришли, тело пустое. roles — кому открыт
 * маршрут; по умолчанию — эмитенту (ISSUER).
 */
function verifyRead(requests: ParticipantRequestVerifier, req: FastifyRequest, roles?: ReadonlySet<ParticipantRole>) {
  const url = req.raw.url ?? "";
  const q = url.indexOf("?");
  return requests.verify(
    {
      method: req.method,
      path: q < 0 ? url : url.slice(0, q),
      query: q < 0 ? "" : url.slice(q + 1),
      headers: req.headers,
      body: "",
    },
    roles,
  );
}
