// Эквайрер стенда как участник ПИ-8 (РП57 п. 1, 7): роль ACQUIRER, перечень своих продавцов, подписывает записи знака
// готовности и запросы чтения. Пара ключей — только в памяти процесса, на диск не пишется; код эмулятора в рабочем
// сервере — отказ запуска (TrustedParticipants).
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { signRequest } from "@kuzin4u/agentic-core";
import { ED25519, parseKey } from "../../registry/keys.js";
import {
  participantPaymentMetadataSigningInput,
  participantReadinessSigningInput,
  STAND_ACQUIRER_CODE,
  type PaymentMetadataSignedRecord,
  type ReadinessSignedRecord,
  type TrustedParticipantKey,
} from "../../participants/trusted.js";
import { PARTICIPANT_COMPONENTS } from "../../participants/verify.js";

export interface AcquirerParticipant {
  readonly participant_code: string;
  /** Открытый ключ для списка доверенных стенда: роль ACQUIRER и перечень продавцов. */
  readonly trustedKey: TrustedParticipantKey;
  /** Подпись записи знака готовности (base64url, РП57 п. 2). */
  signReadiness(record: ReadinessSignedRecord): string;
  /** Подпись метаданных пакета за продавца (base64url, РП57 п. 5). */
  signPaymentMetadata(record: PaymentMetadataSignedRecord): string;
  /** Заголовки подписанного запроса эквайрера без тела (RFC 9421, РП46 (в)) — для чтений ПИ-8. */
  signRequest(method: string, path: string, query: string, at: Date): Record<string, string>;
}

export function createAcquirerParticipant(merchants: readonly string[], participant_code = STAND_ACQUIRER_CODE): AcquirerParticipant {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const parsed = parseKey([ED25519], "ed25519", public_key);
  if (!parsed) throw new Error("эмулятор эквайрера: ключ не разобран");
  const secret: KeyObject = privateKey;
  return {
    participant_code,
    trustedKey: { participant_code, kid: parsed.kid, alg: "ed25519", public_key, role: "ACQUIRER", merchants: [...merchants] },
    signReadiness: (record) => sign(null, participantReadinessSigningInput(record), secret).toString("base64url"),
    signPaymentMetadata: (record) => sign(null, participantPaymentMetadataSigningInput(record), secret).toString("base64url"),
    signRequest: (method, path, query, at) =>
      signRequest(
        {
          method,
          path,
          query,
          body: "",
          headers: { "x-participant-code": participant_code, "x-timestamp": at.toISOString(), "x-nonce": randomUUID() },
        },
        { kid: parsed.kid, alg: "ed25519", sign: (data) => sign(null, data, secret) },
        PARTICIPANT_COMPONENTS,
      ).headers,
  };
}
