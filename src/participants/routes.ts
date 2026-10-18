// П10 Шлюз участников, ПИ-8 (PROCESSING-INTERFACE §11): подпись мандата клиентом в приложении банка (РП12, РП36).
// Неаутентифицированной точки нет, в том числе на стенде: каждое решение — запись участника с его подписью Ed25519
// над хэшем мандата (РП36 п. 3–4). Подпись запроса по RFC 9421 и реестр участников — PS-20 (STATUS «Открыто»).
import type { FastifyInstance } from "fastify";
import { ConsentSignRejected, type ConsentJournal, type SignaturePolicy } from "../consent/journal.js";
import {
  ConsentIntegrityError,
  ConsentStateUnknown,
  MANDATE_ID,
  parseRfc3339,
  type MandateDecisionPayload,
} from "../consent/model.js";
import type { Params } from "../shared/config.js";
import type { TrustedParticipants } from "./trusted.js";

export interface ParticipantDeps {
  readonly trusted: TrustedParticipants;
  readonly consent: ConsentJournal;
  readonly params: SignaturePolicy & Pick<Params, "unavailable_retry_after_sec">;
}

/** Коды ответа ПИ-8 подписи (processing-interface.yaml); тело ошибки — `{code}`, причина — в журнале процесса. */
const HTTP: Readonly<Record<string, number>> = {
  REQUEST_INVALID: 400,
  SIGNATURE_INVALID: 401,
  MANDATE_NOT_FOUND: 404,
  MANDATE_HASH_MISMATCH: 409,
  MANDATE_NOT_PENDING: 409,
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
  if (!/^[0-9a-f]{64}$/.test(o.mandate_hash as string)) return undefined;
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

export async function participantRoutes(app: FastifyInstance, deps: ParticipantDeps): Promise<void> {
  // Неразборный JSON и иные отказы Fastify до обработчика — тело ПИ-8 `{code}`, а не тело Fastify (как в ПАО).
  app.setErrorHandler((err: { statusCode?: number }, _req, reply) => {
    const http = err.statusCode ?? 500;
    if (http === 413) return reply.code(413).send({ code: "REQUEST_INVALID" });
    if (http >= 400 && http < 500) return reply.code(400).send({ code: "REQUEST_INVALID" });
    return reply.code(503).header("retry-after", String(deps.params.unavailable_retry_after_sec)).send({ code: "UPSTREAM_UNAVAILABLE" });
  });
  app.post<{ Params: { id: string } }>("/participants/v1/mandates/:id/sign", async (req, reply) => {
    const fail = (code: keyof typeof HTTP) => {
      const http = HTTP[code]!;
      if (http === 503) void reply.header("retry-after", String(deps.params.unavailable_retry_after_sec));
      return reply.code(http).send({ code });
    };
    const id = req.params.id;
    const d = MANDATE_ID.test(id) ? signBody(id, req.body) : undefined;
    if (!d) return fail("REQUEST_INVALID");
    try {
      const { signature, ...record } = d;
      const r = await deps.consent.sign(d, () => deps.trusted.verify(d.participant_code, d.kid, record, signature), deps.params);
      req.log.info(
        { participant_code: d.participant_code, mandate_id: id, decision: d.decision, status: r.status },
        r.replayed ? "ПИ-8: повтор той же подписи — решение уже записано, записи нет" : "ПИ-8: решение клиента записано",
      );
      return reply.code(200).send({ mandate_id: r.id, status: r.status });
    } catch (err) {
      if (err instanceof ConsentSignRejected) {
        req.log.info({ participant_code: d.participant_code, mandate_id: id, reason: err.reason, status: err.status }, "ПИ-8: решение не записано");
        return fail(err.reason);
      }
      if (err instanceof ConsentIntegrityError || err instanceof ConsentStateUnknown) {
        req.log.error({ err, mandate_id: id }, "ПИ-8: журнал согласий — состояние не подтверждено");
        return fail("STATE_UNAVAILABLE");
      }
      req.log.error({ err, mandate_id: id }, "ПИ-8: сбой журнала согласий");
      return fail("UPSTREAM_UNAVAILABLE");
    }
  });
}
