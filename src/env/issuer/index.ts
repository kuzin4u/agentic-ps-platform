// Эмулятор окружения (issuer) — SPEC §9, каноническая модель (РП6).
// Приложение банка на стенде (РП36 п. 4): клиент подписывает мандат простой ЭП по договору с банком, банк подписывает
// своим тестовым ключом запись о решении или об отзыве (РП38) над хэшем мандата. Пара ключей — только в памяти процесса,
// на диск не пишется.
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { ED25519, parseKey } from "../../registry/keys.js";
import {
  participantRevocationSigningInput,
  participantSigningInput,
  STAND_ISSUER_CODE,
  STAND_REVOCATION_ORDER,
  type ParticipantRevocationRecord,
  type ParticipantSignedRecord,
  type TrustedParticipantKey,
} from "../../participants/trusted.js";

export const component = "env/issuer";

export interface IssuerEmulator {
  readonly participant_code: string;
  /** Открытый ключ для списка доверенных стенда. */
  readonly trustedKey: TrustedParticipantKey;
  /** Подпись записи о решении клиента (base64url). */
  signRecord(record: ParticipantSignedRecord): string;
  /** Подпись записи об отзыве клиентом (base64url, РП38). */
  signRevocation(record: ParticipantRevocationRecord): string;
}

export function createIssuerEmulator(): IssuerEmulator {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const parsed = parseKey([ED25519], "ed25519", public_key);
  if (!parsed) throw new Error("эмулятор эмитента: ключ не разобран");
  const secret: KeyObject = privateKey;
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
  };
}
