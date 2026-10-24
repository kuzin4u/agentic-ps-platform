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

/** Код эмулятора оператора УПК стенда (РП51 п. 12): роль UPK, ключ при старте стенда и только в памяти. */
export const STAND_UPK_CODE = "stand:upk-emulator";

/** Код эмулятора эквайрера стенда (РП57 п. 1): роль ACQUIRER, ключ при старте стенда и только в памяти. */
export const STAND_ACQUIRER_CODE = "stand:acquirer-emulator";

/** Коды эмуляторов стенда: в рабочем сервере — отказ запуска при любой роли. */
const STAND_CODES: ReadonlySet<string> = new Set([STAND_ISSUER_CODE, STAND_UPK_CODE, STAND_ACQUIRER_CODE]);

/**
 * Роль участника (РП51 п. 12, РП57 п. 1): ISSUER — банк (мандаты, отзыв, лимиты, лента, решение по подтверждению своего
 * клиента); UPK — оператор страницы УПК, подписывает только решения по подтверждению; ACQUIRER — эквайрер, подписывает
 * только маршруты эквайрера ПИ-8 (знак, метаданные, статус агента) и только для продавцов из своего перечня. Боевой UPK —
 * отказ запуска: решение оператора не привязано к аутентификации у эмитента, подделанное одобрение неотличимо от настоящего.
 */
export type ParticipantRole = "ISSUER" | "UPK" | "ACQUIRER";

/** Метка подписи записи знака готовности (РП57 п. 2): своя — подписи других записей участника не подходят. */
export const PARTICIPANT_READINESS_CONTEXT = "pao:participant-merchant-readiness:v1";

/** Метка подписи метаданных пакета (РП57 п. 5): своя — подпись записи знака как метаданные не годится, и наоборот. */
export const PARTICIPANT_PAYMENT_METADATA_CONTEXT = "pao:participant-payment-metadata:v1";

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
  /** Роль (РП51 п. 12); нет — ISSUER. У всех ключей участника одна. */
  readonly role?: ParticipantRole;
  /** Порядок отзыва — ссылка на соглашение банка с клиентом (РП37); у всех ключей участника одна. У UPK — нет. */
  readonly revocation_order?: string;
  /**
   * Адрес вебхука-сигнала уведомлений клиента (РП46 доп. п. 9 (о4)) — часть соглашения с банком, у всех ключей участника
   * один; смена — новой записью участника. Нет — уведомления только лентой. Форма и адреса имени — при каждой отправке.
   */
  readonly notify_url?: string;
  /** Перечень продавцов эквайрера (РП57 п. 1): у ACQUIRER обязателен и непуст, у всех ключей один; у прочих ролей — нет. */
  readonly merchants?: readonly string[];
}

/** merchant_id — как в POST /pao/v1/credentials: непустая строка до 128 знаков (processing-interface.yaml, MerchantId). */
export const MERCHANT_ID_MAX = 128;
export const isMerchantId = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MERCHANT_ID_MAX;

/** Порядок отзыва на стенде (РП37 п. 5). */
export const STAND_REVOCATION_ORDER = "bank:stand:issuer-emulator:revocation:v1";

const REVOCATION_ORDER = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/;

export interface TrustedParticipantsOptions {
  /** Стенд (РП25): разрешён ключ эмулятора эмитента. В рабочем сервере — false. */
  readonly stand: boolean;
}

/** Ровно поля записи файла (РП36 доп. п. 7); role — необязательное (РП51 п. 12). */
const FILE_FIELDS = "alg,kid,participant_code,public_key,revocation_order";

export class TrustedParticipants {
  private readonly keys = new Map<string, KeyObject>();
  /** Порядок отзыва по участнику (РП37). */
  private readonly orders = new Map<string, string>();
  /** Адрес вебхука по участнику (РП46 доп. п. 9 (о4)); null — у участника вебхука нет. */
  private readonly notifyUrls = new Map<string, string | null>();
  /** Роль по участнику (РП51 п. 12). */
  private readonly roles = new Map<string, ParticipantRole>();
  /** Эквайрер продавца (РП57 п. 1): один продавец — один эквайрер. */
  private readonly acquirers = new Map<string, string>();
  /** Перечень продавцов по эквайреру — для сверки записей ключей одного участника. */
  private readonly merchantLists = new Map<string, string>();

  constructor(list: readonly TrustedParticipantKey[], opts: TrustedParticipantsOptions) {
    const live = new Set<string>();
    for (const k of list) {
      if (typeof k.participant_code !== "string" || !PARTICIPANT_CODE.test(k.participant_code)) {
        throw new Error(`Доверенные участники: недопустимый participant_code «${String(k.participant_code)}»`);
      }
      // Ключа нет — ISSUER; ключ есть — только ISSUER, UPK или ACQUIRER: null и прочее — отказ, а не банк по умолчанию (fail-closed).
      const role = "role" in k ? k.role : "ISSUER";
      if (role !== "ISSUER" && role !== "UPK" && role !== "ACQUIRER") {
        throw new Error(`Доверенные участники: недопустимая role «${String(role)}» у ${k.participant_code} (РП51 п. 12, РП57 п. 1)`);
      }
      if (this.roles.has(k.participant_code) && this.roles.get(k.participant_code) !== role) {
        throw new Error(`Доверенные участники: у ${k.participant_code} разные role в записях ключей (РП51 п. 12)`);
      }
      this.roles.set(k.participant_code, role);
      if (role === "UPK" && !opts.stand) {
        // Боевой UPK — отказ запуска (РП51 п. 12, ревью № 1): снять — только с привязкой к аутентификации у эмитента.
        throw new Error(
          `Доверенные участники: участник ${k.participant_code} с ролью UPK допустим только на стенде — решение оператора УПК ` +
            `не привязано к аутентификации у эмитента (РП51 п. 12)`,
        );
      }
      if ((k.participant_code === STAND_UPK_CODE) !== (role === "UPK")) {
        throw new Error(`Доверенные участники: роль UPK — только у эмулятора ${STAND_UPK_CODE} и только на стенде (РП51 п. 12)`);
      }
      // Коды эмуляторов стенда вне стенда — отказ при любой роли (ревью КТ1 PS-30 ч. 2 № 11): иначе эквайрер с кодом
      // stand:issuer-emulator путал бы журнал процесса.
      if (!opts.stand && STAND_CODES.has(k.participant_code)) {
        throw new Error(`Доверенные участники: код эмулятора ${k.participant_code} допустим только на стенде (РП36 доп., РП51 п. 12, РП57 п. 1)`);
      }
      if (k.participant_code === STAND_ACQUIRER_CODE && (role !== "ACQUIRER" || !opts.stand)) {
        throw new Error(`Доверенные участники: ключ эмулятора ${STAND_ACQUIRER_CODE} — роль ACQUIRER и только на стенде (РП57 п. 1)`);
      }
      if (role !== "ACQUIRER" && k.merchants !== undefined) {
        throw new Error(`Доверенные участники: перечень merchants — только у роли ACQUIRER, у ${k.participant_code} — ${role} (РП57 п. 1)`);
      }
      if (role === "ACQUIRER") {
        // Эквайрер (РП57 п. 1): только перечень продавцов; порядка отзыва и вебхука нет — он не банк клиента.
        if (k.revocation_order !== undefined || k.notify_url !== undefined) {
          throw new Error(`Доверенные участники: у ${k.participant_code} (ACQUIRER) нет revocation_order и notify_url (РП57 п. 1)`);
        }
        const merchants = k.merchants;
        if (!Array.isArray(merchants) || merchants.length === 0 || !merchants.every(isMerchantId) || new Set(merchants).size !== merchants.length) {
          throw new Error(`Доверенные участники: у ${k.participant_code} (ACQUIRER) перечень merchants — непустой, без повторов, merchant_id до ${MERCHANT_ID_MAX} знаков (РП57 п. 1)`);
        }
        const listKey = JSON.stringify([...merchants].sort());
        const known = this.merchantLists.get(k.participant_code);
        if (known !== undefined && known !== listKey) {
          throw new Error(`Доверенные участники: у ${k.participant_code} разные перечни merchants в записях ключей (РП57 п. 1)`);
        }
        if (known === undefined) {
          this.merchantLists.set(k.participant_code, listKey);
          for (const m of merchants) {
            // Один продавец — один эквайрер (РП57 п. 1, вопрос 1): иначе чей знак действует — неоднозначно (fail-closed).
            const other = this.acquirers.get(m);
            if (other !== undefined) {
              throw new Error(`Доверенные участники: продавец ${m} в перечнях двух эквайреров (${other}, ${k.participant_code}) — один продавец, один эквайрер (РП57 п. 1)`);
            }
            this.acquirers.set(m, k.participant_code);
          }
        }
      } else if (role === "UPK") {
        if (k.revocation_order !== undefined) {
          throw new Error(`Доверенные участники: у ${k.participant_code} (UPK) порядка отзыва нет — он не банк клиента (РП51 п. 12)`);
        }
      } else {
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
      }
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

  /** Роль участника (РП51 п. 12); неизвестный — undefined. */
  role(participant_code: string): ParticipantRole | undefined {
    return this.roles.get(participant_code);
  }

  /** Продавец в перечне этого эквайрера (РП57 п. 1); не эквайрер или чужой продавец — false. */
  serves(participant_code: string, merchant_id: string): boolean {
    return this.acquirers.get(merchant_id) === participant_code;
  }

  /** Подпись эквайрера над записью знака готовности (РП57 п. 2): только роль ACQUIRER, своя метка. */
  verifyReadiness(record: ReadinessSignedRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantReadinessSigningInput(record), signature, ACQUIRER_ONLY);
  }

  /** Подпись эквайрера над метаданными пакета (РП57 п. 5): только роль ACQUIRER, своя метка. */
  verifyPaymentMetadata(record: PaymentMetadataSignedRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantPaymentMetadataSigningInput(record), signature, ACQUIRER_ONLY);
  }

  /**
   * Подпись участника над записью о решении; неизвестный участник или ключ — false, как неверная подпись. Здесь и в
   * прочих проверках банка UPK — false, как чужой банк (РП51 п. 12): он подписывает только решения по подтверждению.
   */
  verify(participant_code: string, kid: string, record: ParticipantSignedRecord, signature: string): boolean {
    return this.verifyInput(participant_code, kid, participantSigningInput(record), signature, ISSUER_ONLY);
  }

  /** Подпись участника над записью об отзыве (РП38): метка отзыва, подпись решения не подходит. */
  verifyRevocation(record: ParticipantRevocationRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantRevocationSigningInput(record), signature, ISSUER_ONLY);
  }

  /** Подпись участника над записью отзыва всех полномочий клиента (РП45 п. 4): своя метка. */
  verifyPrincipalRevocation(record: ParticipantPrincipalRevocationRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantPrincipalRevocationSigningInput(record), signature, ISSUER_ONLY);
  }

  /** Подпись участника над записью лимитов клиента (РП45 п. 1): своя метка, подпись решения или отзыва не подходит. */
  verifyLimits(record: LimitsRecord, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantLimitsSigningInput(record), signature, ISSUER_ONLY);
  }

  /** Подпись участника над решением человека по запросу подтверждения (РП50 п. 4, РП51 п. 12–13): банк или UPK. */
  verifyConfirmation(record: Omit<ConfirmationDecision, "signature"> & { readonly confirmation_id: string }, signature: string): boolean {
    return this.verifyInput(record.participant_code, record.kid, participantConfirmationSigningInput(record), signature, ANY_ROLE);
  }

  /**
   * Подпись Ed25519 над готовыми байтами (основа подписи запроса RFC 9421, РП46 (в)); неизвестный ключ и роль вне roles —
   * false. По умолчанию — только ISSUER (чтения эмитента); чтения эквайрера — ACQUIRER (РП57 п. 3, 6).
   */
  verifyRaw(participant_code: string, kid: string, data: Buffer, sig: Buffer, roles: ReadonlySet<ParticipantRole> = ISSUER_ONLY): boolean {
    if (!roles.has(this.roles.get(participant_code) as ParticipantRole)) return false;
    const key = this.keys.get(keyId(participant_code, kid));
    return key !== undefined && sig.length === 64 && verify(null, data, key, sig);
  }

  private verifyInput(participant_code: string, kid: string, input: Buffer, signature: string, roles: ReadonlySet<ParticipantRole>): boolean {
    if (!roles.has(this.roles.get(participant_code) as ParticipantRole)) return false;
    const key = this.keys.get(keyId(participant_code, kid));
    if (!key) return false;
    const sig = Buffer.from(signature, "base64url");
    if (sig.length !== 64 || sig.toString("base64url") !== signature) return false;
    return verify(null, input, key, sig);
  }
}

const keyId = (participant_code: string, kid: string): string => `${participant_code}\n${kid}`;

export const ISSUER_ONLY: ReadonlySet<ParticipantRole> = new Set(["ISSUER"]);
export const ACQUIRER_ONLY: ReadonlySet<ParticipantRole> = new Set(["ACQUIRER"]);
const ANY_ROLE: ReadonlySet<ParticipantRole> = new Set(["ISSUER", "UPK"]);

/** Подписываемая эквайрером запись знака готовности (РП57 п. 2); метка контекста добавляется при подписи. */
export interface ReadinessSignedRecord {
  readonly participant_code: string;
  readonly kid: string;
  readonly merchant_id: string;
  readonly readiness_ref: string;
  readonly status: "ACTIVE" | "WITHDRAWN";
  readonly issued_at: string;
}

/** Подписываемая эквайрером запись метаданных пакета за продавца (РП57 п. 5); aoi — если эквайрер получил его из пакета. */
export interface PaymentMetadataSignedRecord {
  readonly participant_code: string;
  readonly kid: string;
  readonly merchant_id: string;
  readonly metadata_ref: string;
  readonly credential_ref: string;
  readonly order_ref: string;
  readonly aoi?: { readonly agent_code: string; readonly mandate_id: string };
  readonly submitted_at: string;
}

/** Байты подписи метаданных: canonicalJson записи с меткой; без aoi ключа aoi в записи нет (не null). */
export const participantPaymentMetadataSigningInput = (r: PaymentMetadataSignedRecord): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_PAYMENT_METADATA_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      merchant_id: r.merchant_id,
      metadata_ref: r.metadata_ref,
      credential_ref: r.credential_ref,
      order_ref: r.order_ref,
      ...(r.aoi ? { aoi: { agent_code: r.aoi.agent_code, mandate_id: r.aoi.mandate_id } } : {}),
      submitted_at: r.submitted_at,
    }),
    "utf8",
  );

/** Байты подписи знака: canonicalJson записи с меткой pao:participant-merchant-readiness:v1, UTF-8. */
export const participantReadinessSigningInput = (r: ReadinessSignedRecord): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_READINESS_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      merchant_id: r.merchant_id,
      readiness_ref: r.readiness_ref,
      status: r.status,
      issued_at: r.issued_at,
    }),
    "utf8",
  );

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
 * Список доверенных ключей из файла PARTICIPANT_KEYS_PATH: `{"participants": [{participant_code, kid, alg, public_key, revocation_order, role?}]}`.
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
    // role — необязательное (РП51 п. 12); UPK в рабочем сервере отвергнет конструктор. У ACQUIRER вместо порядка отзыва —
    // перечень merchants (РП57 п. 1); его форму проверяет конструктор.
    const fields = k !== null && typeof k === "object" ? Object.keys(k).filter((f) => f !== "role").sort().join(",") : "";
    const role = (k as { role?: unknown } | null)?.role;
    const ok =
      fields === FILE_FIELDS ||
      (fields === "alg,kid,participant_code,public_key" && role === "UPK") ||
      (fields === "alg,kid,merchants,participant_code,public_key" && role === "ACQUIRER");
    if (!ok) {
      throw new Error(
        `PARTICIPANT_KEYS_PATH=${path}: запись — ровно participant_code, kid, alg, public_key, revocation_order и необязательное role; ` +
          `у role ACQUIRER — merchants вместо revocation_order`,
      );
    }
  }
  return new TrustedParticipants(list as TrustedParticipantKey[], opts);
}
