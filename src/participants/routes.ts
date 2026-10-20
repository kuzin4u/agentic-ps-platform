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
import type { StateService } from "../state/service.js";
import { limitsBody, type LimitsStore } from "./limits.js";
import type { TrustedParticipants } from "./trusted.js";

export interface ParticipantDeps {
  readonly trusted: TrustedParticipants;
  readonly consent: ConsentJournal;
  readonly params: SignaturePolicy & Pick<Params, "unavailable_retry_after_sec">;
  /** П3: счёт бюджета открывается после MANDATE_SIGNED (РП41 п. 3); без П3 или при сбое — первым резервом. */
  readonly state?: Pick<StateService, "open">;
  /** Лимиты клиента от банка (РП45 п. 1); без хранилища маршрута лимитов нет. */
  readonly limits?: LimitsStore;
  /** Часы Платформы для received_at записи лимитов. */
  readonly now?: () => Date;
}

/** Коды ответа ПИ-8 подписи (processing-interface.yaml); тело ошибки — `{code}`, причина — в журнале процесса. */
const HTTP: Readonly<Record<string, number>> = {
  REQUEST_INVALID: 400,
  SIGNATURE_INVALID: 401,
  MANDATE_NOT_FOUND: 404,
  MANDATE_HASH_MISMATCH: 409,
  MANDATE_NOT_PENDING: 409,
  LIMITS_VERSION_CONFLICT: 409,
  LIMITS_UNSUPPORTED: 422,
  QUALIFIED_SIGNATURE_REQUIRED: 422,
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
}
