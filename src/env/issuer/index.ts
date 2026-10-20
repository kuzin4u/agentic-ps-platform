// Эмулятор окружения (issuer) — SPEC §9, каноническая модель (РП6).
// Приложение банка на стенде (РП36 п. 4): клиент подписывает мандат простой ЭП по договору с банком, банк подписывает
// своим тестовым ключом запись о решении или об отзыве (РП38) над хэшем мандата. Пара ключей — только в памяти процесса,
// на диск не пишется.
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { signRequest } from "@kuzin4u/agentic-core";
import { ED25519, parseKey } from "../../registry/keys.js";
import {
  participantPrincipalRevocationSigningInput,
  participantRevocationSigningInput,
  participantSigningInput,
  STAND_ISSUER_CODE,
  STAND_REVOCATION_ORDER,
  type ParticipantPrincipalRevocationRecord,
  type ParticipantRevocationRecord,
  type ParticipantSignedRecord,
  type TrustedParticipantKey,
} from "../../participants/trusted.js";
import { participantLimitsSigningInput, type LimitsRecord } from "../../participants/limits.js";
import { opaqueRef } from "../../credentials/model.js";
import { PARTICIPANT_COMPONENTS } from "../../participants/verify.js";

export const component = "env/issuer";

export interface IssuerEmulator {
  readonly participant_code: string;
  /** Открытый ключ для списка доверенных стенда. */
  readonly trustedKey: TrustedParticipantKey;
  /** Подпись записи о решении клиента (base64url). */
  signRecord(record: ParticipantSignedRecord): string;
  /** Подпись записи об отзыве клиентом (base64url, РП38). */
  signRevocation(record: ParticipantRevocationRecord): string;
  /** Подпись записи отзыва всех полномочий клиента (base64url, РП45 п. 4). */
  signPrincipalRevocation(record: ParticipantPrincipalRevocationRecord): string;
  /** Подпись записи лимитов клиента (base64url, РП45 п. 1). */
  signLimits(record: LimitsRecord): string;
  /** Заголовки подписанного запроса участника без тела (RFC 9421, РП46 (в)): чтения ПИ-8. */
  signRequest(method: string, path: string, query: string, at: Date): Record<string, string>;
  /**
   * Ссылка банка на карту клиента для выпуска агентского токена (ПИ-4, РП47 п. 2): одна на клиента, без номера карты
   * (инвариант 1). Клиент другого банка — исключение.
   */
  fundingRef(client: { readonly participant_code: string; readonly principal_ref: string }): Promise<string>;
}

export function createIssuerEmulator(): IssuerEmulator {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const parsed = parseKey([ED25519], "ed25519", public_key);
  if (!parsed) throw new Error("эмулятор эмитента: ключ не разобран");
  const secret: KeyObject = privateKey;
  const funding = new Map<string, string>();
  return {
    participant_code: STAND_ISSUER_CODE,
    trustedKey: {
      participant_code: STAND_ISSUER_CODE,
      kid: parsed.kid,
      alg: "ed25519",
      public_key,
      revocation_order: STAND_REVOCATION_ORDER,
    },
    signRecord: (record) => sign(null, participantSigningInput(record), secret).toString("base64url"),
    signRevocation: (record) => sign(null, participantRevocationSigningInput(record), secret).toString("base64url"),
    signPrincipalRevocation: (record) => sign(null, participantPrincipalRevocationSigningInput(record), secret).toString("base64url"),
    signRequest: (method, path, query, at) =>
      signRequest(
        {
          method,
          path,
          query,
          body: "",
          headers: { "x-participant-code": STAND_ISSUER_CODE, "x-timestamp": at.toISOString(), "x-nonce": randomUUID() },
        },
        { kid: parsed.kid, alg: "ed25519", sign: (data) => sign(null, data, secret) },
        PARTICIPANT_COMPONENTS,
      ).headers,
    signLimits: (record) => sign(null, participantLimitsSigningInput(record), secret).toString("base64url"),
    async fundingRef({ participant_code, principal_ref }) {
      if (participant_code !== STAND_ISSUER_CODE) throw new Error("эмулятор эмитента: клиент другого банка");
      let ref = funding.get(principal_ref);
      if (ref === undefined) funding.set(principal_ref, (ref = opaqueRef("fnd_")));
      return ref;
    },
  };
}
