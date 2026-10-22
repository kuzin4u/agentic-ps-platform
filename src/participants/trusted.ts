// П10 Доверенные ключи участников до шлюза участников (РП36 п. 4; PS-20 расширит): подпись банка над хэшем мандата.
// Ключей и данных входа клиентов у Платформы нет — только открытые ключи банков (РП36 п. 3, 5).
// Fail-closed: файл задан, но не читается или неверен — отказ запуска; списка нет или он пуст — подпись отклоняется всем.
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalJson } from "@kuzin4u/agentic-core";
import type { MandateDecisionPayload, MandateRevocationPayload, PrincipalRevocationPayload } from "../consent/model.js";
import { ED25519, parseKey } from "../registry/keys.js";
import { participantConfirmationSigningInput, type ConfirmationDecision } from "../confirm/model.js";
import { participantLimitsSigningInput, type LimitsRecord } from "./limits.js";

/** Метка контекста подписи участника (РП36 доп.): подпись банка пригодна только для подписи мандата этой версии. */
export const PARTICIPANT_SIGNATURE_CONTEXT = "pao:participant-mandate-signature:v1";

/** Метка контекста отзыва (РП38 п. 1): своя — подпись решения не годится как отзыв, и наоборот. */
export const PARTICIPANT_REVOCATION_CONTEXT = "pao:participant-mandate-revocation:v1";

/** Метка отзыва всех полномочий клиента (РП45 п. 4): своя — подпись отзыва одного мандата не годится, и наоборот. */
export const PARTICIPANT_PRINCIPAL_REVOCATION_CONTEXT = "pao:participant-principal-revocation:v1";

/** Код эмулятора эмитента стенда: ключ создаётся при старте стенда и только в памяти; в рабочем сервере — отказ запуска. */
export const STAND_ISSUER_CODE = "stand:issuer-emulator";

/**
 * Не больше одного боевого участника (эмулятор стенда не считается), пока мандат не привязан к банку (РП36 доп.):
 * иначе банк Б подписал бы мандат клиента банка А. Привязка — Б2, вместе с форматом principal_ref.
 */
export const MAX_LIVE_PARTICIPANTS = 1;

const PARTICIPANT_CODE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$/;

export interface TrustedParticipantKey {
  readonly participant_code: string;
  readonly kid: string;
  readonly alg: string;
  /** DER SPKI, каноническая запись base64 (как у агентов, РП23 доп. 6). */
  readonly public_key: string;
  /** Порядок отзыва — ссылка на соглашение банка с клиентом (РП37); у всех ключей участника одна. */
  readonly revocation_order: string;
  /**
   * Адрес вебхука-сигнала уведомлений клиента (РП46 доп. п. 9 (о4)) — часть соглашения с банком, у всех ключей участника
   * один; смена — новой записью участника. Нет — уведомления только лентой. Форма и адреса имени — при каждой отправке.
   */
  readonly notify_url?: string;
}

/** Порядок отзыва на стенде (РП37 п. 5). */
export const STAND_REVOCATION_ORDER = "bank:stand:issuer-emulator:revocation:v1";

const REVOCATION_ORDER = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/;

export interface TrustedParticipantsOptions {
  /** Стенд (РП25): разрешён ключ эмулятора эмитента. В рабочем сервере — false. */
  readonly stand: boolean;
}

export class TrustedParticipants {
  private readonly keys = new Map<string, KeyObject>();
  /** Порядок отзыва по участнику (РП37). */
  private readonly orders = new Map<string, string>();
  /** Адрес вебхука по участнику (РП46 доп. п. 9 (о4)); null — у участника вебхука нет. */
  private readonly notifyUrls = new Map<string, string | null>();

  constructor(list: readonly TrustedParticipantKey[], opts: TrustedParticipantsOptions) {
    const live = new Set<string>();
    for (const k of list) {
      if (typeof k.participant_code !== "string" || !PARTICIPANT_CODE.test(k.participant_code)) {
        throw new Error(`Доверенные участники: недопустимый participant_code «${String(k.participant_code)}»`);
      }
      if (k.participant_code === STAND_ISSUER_CODE) {
        if (!opts.stand) {
          throw new Error(`Доверенные участники: ключ эмулятора ${STAND_ISSUER_CODE} допустим только на стенде (РП36 доп.)`);
        }
      } else {
        live.add(k.participant_code);
      }
      if (typeof k.revocation_order !== "string" || !REVOCATION_ORDER.test(k.revocation_order)) {
        throw new Error(`Доверенные участники: недопустимый revocation_order у ${k.participant_code} (РП37)`);
      }
      const known = this.orders.get(k.participant_code);
      if (known !== undefined && known !== k.revocation_order) {
        throw new Error(`Доверенные участники: у ${k.participant_code} разные revocation_order в записях ключей (РП37)`);
      }
      this.orders.set(k.participant_code, k.revocation_order);
      // Адрес вебхука: строка https:// до 2048 знаков (полная проверка — перед каждой отправкой, как РП40 п. 4).
      const url = k.notify_url ?? null;
      if (url !== null && (typeof url !== "string" || url.length > 2048 || !/^https:\/\//i.test(url))) {
        throw new Error(`Доверенные участники: недопустимый notify_url у ${k.participant_code} (РП46 доп. п. 9)`);
      }
      if (this.notifyUrls.has(k.participant_code) && this.notifyUrls.get(k.participant_code) !== url) {
        throw new Error(`Доверенные участники: у ${k.participant_code} разные notify_url в записях ключей (РП46 доп. п. 9)`);
      }
      this.notifyUrls.set(k.participant_code, url);
      // Тот же разбор, что у ключей агентов: каноническая запись, ed25519, слабые ключи — отказ.
      const parsed = parseKey([ED25519], k.alg, k.public_key);
      if (!parsed) throw new Error(`Доверенные участники: ключ ${k.participant_code}/${String(k.kid)} не принят (ed25519, DER SPKI base64)`);
      if (parsed.kid !== k.kid) throw new Error(`Доверенные участники: kid ${String(k.kid)} ≠ отпечатку RFC 7638 ключа ${k.participant_code}`);
      const id = keyId(k.participant_code, k.kid);
      if (this.keys.has(id)) throw new Error(`Доверенные участники: ключ ${id} указан дважды`);
      this.keys.set(id, createPublicKey({ key: Buffer.from(k.public_key, "base64"), format: "der", type: "spki" }));
    }
    if (live.size > MAX_LIVE_PARTICIPANTS) {
      throw new Error(
        `Доверенные участники: ${live.size} боевых участника (${[...live].join(", ")}) — до привязки мандата к банку ` +
          `(Б2, формат principal_ref) допустим не больше ${MAX_LIVE_PARTICIPANTS} (РП36 доп.); второй банк — решение владельца`,
      );
    }
  }

  /**
   * Порядок отзыва для нового мандата (РП37): боевой участник (он один, РП36 доп. п. 8), иначе эмулятор стенда;
   * участников нет — undefined, мандат не пишется (503).
   */
  revocationOrder(): string | undefined {
    for (const [code, order] of this.orders) if (code !== STAND_ISSUER_CODE) return order;
    return this.orders.get(STAND_ISSUER_CODE);
  }

  /** Адрес вебхука участника (РП46 доп. п. 9 (о4)); нет или участник неизвестен — undefined (только лента). */
  notifyUrl(participant_code: string): string | undefined {
    return this.notifyUrls.get(participant_code) ?? undefined;
  }

  /** Подпись участника над записью о решении; неизвестный участник или ключ — false, как неверная подпись. */
  verify(participant_code: string, kid: string, record: ParticipantSignedRecord, signature: string): boolean {
    return this.verifyInput(participant_code, kid, participantSigningInput(record), signature);
  }

  /** Подпись участника над записью об отзыве (РП38): метка отзыва, подпись решения не подходит. */
  verifyRevocation(record: ParticipantRevocationRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantRevocationSigningInput(record), signature);
  }

  /** Подпись участника над записью отзыва всех полномочий клиента (РП45 п. 4): своя метка. */
  verifyPrincipalRevocation(record: ParticipantPrincipalRevocationRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantPrincipalRevocationSigningInput(record), signature);
  }

  /** Подпись участника над записью лимитов клиента (РП45 п. 1): своя метка, подпись решения или отзыва не подходит. */
  verifyLimits(record: LimitsRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantLimitsSigningInput(record), signature);
  }

  /** Подпись участника над решением человека по запросу подтверждения (РП50 п. 4): своя метка. */
  verifyConfirmation(record: Omit<ConfirmationDecision, "signature"> & { readonly confirmation_id: string }, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantConfirmationSigningInput(record), signature);
  }

  /** Подпись Ed25519 над готовыми байтами (основа подписи запроса RFC 9421, РП46 (в)); неизвестный ключ — false. */
  verifyRaw(participant_code: string, kid: string, data: Buffer, sig: Buffer): boolean {
    const key = this.keys.get(keyId(participant_code, kid));
    return key !== undefined && sig.length === 64 && verify(null, data, key, sig);
  }

  private verifyInput(participant_code: string, kid: string, input: Buffer, signature: string): boolean {
    const key = this.keys.get(keyId(participant_code, kid));
    if (!key) return false;
    const sig = Buffer.from(signature, "base64url");
    if (sig.length !== 64 || sig.toString("base64url") !== signature) return false;
    return verify(null, input, key, sig);
  }
}

const keyId = (participant_code: string, kid: string): string => `${participant_code}\n${kid}`;

/** Подписываемая участником запись о решении клиента (РП36 доп.); метка контекста добавляется при подписи. */
export type ParticipantSignedRecord = Omit<MandateDecisionPayload, "signature">;

/** Байты подписи: canonicalJson записи с меткой контекста, UTF-8. */
export const participantSigningInput = (r: ParticipantSignedRecord): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_SIGNATURE_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      mandate_id: r.mandate_id,
      mandate_hash: r.mandate_hash,
      decision: r.decision,
      signature_type: r.signature_type,
      signature_ref: r.signature_ref,
      token_consent: r.token_consent,
      signed_at: r.signed_at,
    }),
    "utf8",
  );

/** Подписываемая участником запись об отзыве клиентом (РП38 п. 1); метка контекста добавляется при подписи. */
export type ParticipantRevocationRecord = Omit<MandateRevocationPayload, "signature">;

/** Байты подписи отзыва: canonicalJson записи с меткой отзыва, UTF-8. */
export const participantRevocationSigningInput = (r: ParticipantRevocationRecord): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_REVOCATION_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      mandate_id: r.mandate_id,
      mandate_hash: r.mandate_hash,
      revocation_ref: r.revocation_ref,
      revoked_at: r.revoked_at,
    }),
    "utf8",
  );

/** Подписываемая участником запись отзыва всех полномочий клиента (РП45 п. 4); метка добавляется при подписи. */
export type ParticipantPrincipalRevocationRecord = Omit<PrincipalRevocationPayload, "signature">;

/** Байты подписи revoke-all: canonicalJson записи с меткой pao:participant-principal-revocation:v1, UTF-8. */
export const participantPrincipalRevocationSigningInput = (r: ParticipantPrincipalRevocationRecord): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_PRINCIPAL_REVOCATION_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      principal_ref: r.principal_ref,
      revocation_ref: r.revocation_ref,
      revoked_at: r.revoked_at,
    }),
    "utf8",
  );

/**
 * Список доверенных ключей из файла PARTICIPANT_KEYS_PATH: `{"participants": [{participant_code, kid, alg, public_key, revocation_order}]}`.
 * Пути нет — пустой список (подпись отклоняется всем). Файл не читается, не JSON, лишние поля — отказ запуска.
 */
export function loadTrustedParticipants(path: string | undefined, opts: TrustedParticipantsOptions): TrustedParticipants {
  if (path === undefined || path === "") return new TrustedParticipants([], opts);
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`PARTICIPANT_KEYS_PATH=${path}: файл не читается или не JSON (${(err as Error).message})`);
  }
  const list = (doc as { participants?: unknown } | null)?.participants;
  if (!Array.isArray(list) || Object.keys(doc as object).length !== 1) {
    throw new Error(`PARTICIPANT_KEYS_PATH=${path}: ожидается {"participants": [...]}`);
  }
  for (const k of list) {
    const fields = k !== null && typeof k === "object" ? Object.keys(k).sort().join(",") : "";
    if (fields !== "alg,kid,participant_code,public_key,revocation_order") {
      throw new Error(`PARTICIPANT_KEYS_PATH=${path}: запись — ровно participant_code, kid, alg, public_key, revocation_order`);
    }
  }
  return new TrustedParticipants(list as TrustedParticipantKey[], opts);
}
