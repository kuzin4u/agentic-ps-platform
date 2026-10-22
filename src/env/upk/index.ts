// Эмулятор окружения (upk) — SPEC §9, каноническая модель (РП6).
// Оператор УПК на стенде (РП51 п. 12): участник ПИ-8 с ролью UPK, подписывает только решения человека по запросу
// подтверждения. Пара ключей — только в памяти процесса, на диск не пишется; в рабочем сервере роль UPK — отказ запуска.
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { ED25519, parseKey } from "../../registry/keys.js";
import { STAND_UPK_CODE, type TrustedParticipantKey } from "../../participants/trusted.js";
import { participantConfirmationSigningInput, type ConfirmationDecision } from "../../confirm/model.js";

export const component = "env/upk";

export interface UpkEmulator {
  readonly participant_code: string;
  /** Открытый ключ для списка доверенных стенда: роль UPK, порядка отзыва нет. */
  readonly trustedKey: TrustedParticipantKey;
  /** Подпись решения человека по запросу подтверждения (base64url, РП50 п. 4, РП51 п. 13). */
  signConfirmation(record: Omit<ConfirmationDecision, "signature"> & { readonly confirmation_id: string }): string;
}

export function createUpkEmulator(): UpkEmulator {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const parsed = parseKey([ED25519], "ed25519", public_key);
  if (!parsed) throw new Error("эмулятор УПК: ключ не разобран");
  const secret: KeyObject = privateKey;
  return {
    participant_code: STAND_UPK_CODE,
    trustedKey: { participant_code: STAND_UPK_CODE, kid: parsed.kid, alg: "ed25519", public_key, role: "UPK" },
    signConfirmation: (record) => sign(null, participantConfirmationSigningInput(record), secret).toString("base64url"),
  };
}
