// Агентский токен для тестов ADP, где реквизит — не предмет проверки (РП48 (а): CARD_TOKEN с признаком отклоняется,
// агентская операция — только AGENT_TOKEN). Домен токена — из aoi сообщения, реквизит — на продавца, сумму и валюту
// сообщения: проверки 2 и 4 проходят, остальные видят сообщение как прежде. Однократность здесь не проверяется
// (consume всегда успешен) — она в adp-credentials.test.ts и ПС05 на настоящем П5.
import { createHash } from "node:crypto";
import type { AdpCredentials } from "../../src/adp/index.js";
import type { CredentialRecord, TokenRecord } from "../../src/credentials/index.js";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

const tokens = new Map<string, TokenRecord>();
const credentials = new Map<string, CredentialRecord>();

/**
 * Сообщение с AGENT_TOKEN вместо CARD_TOKEN: token_ref и криптограмма — детерминированно от домена и полей сообщения,
 * так что повтор того же op_ref с тем же сообщением даёт тот же хэш сообщения. Без aoi или с другим инструментом —
 * сообщение как есть.
 */
export function agentToken(m: CanonicalMessage): CanonicalMessage {
  if (!m.aoi || m.instrument?.kind !== "CARD_TOKEN") return m;
  const agent_code = m.aoi.agent_code as string;
  const mandate_id = m.aoi.mandate_id as string;
  const token_ref = `tok_agent_${sha(JSON.stringify([agent_code, mandate_id])).slice(0, 16)}`;
  tokens.set(token_ref, {
    token_ref,
    agent_code,
    mandate_id,
    merchant_scope: [],
    valid_to: "2099-01-01T00:00:00Z",
    funding_ref: "fnd_test",
    created_at: "2026-10-01T00:00:00Z",
  });
  const merchant_id = m.merchant?.id as string;
  const cryptogram = sha(JSON.stringify([token_ref, m.op_ref, merchant_id, m.amount, m.currency]));
  const cryptogram_sha256 = sha(cryptogram);
  credentials.set(`${token_ref} ${cryptogram_sha256}`, {
    credential_ref: `crd_${cryptogram_sha256.slice(0, 16)}`,
    agent_code,
    mandate_id,
    token_ref,
    order_ref: m.op_ref,
    merchant_id,
    amount_max: m.amount,
    currency: m.currency,
    valid_to: "2099-01-01T00:00:00Z",
    cryptogram_sha256,
    status: "ISSUED",
    op_ref: null,
    created_at: "2026-10-01T00:00:00Z",
  });
  return { ...m, instrument: { kind: "AGENT_TOKEN", token_ref, cryptogram } };
}

/** Порт П5 для ADP над реквизитами agentToken: погашение не меняет запись (однократность — не предмет этих тестов). */
export const agentTokenCredentials: AdpCredentials = {
  tokenByRef: async (token_ref) => tokens.get(token_ref),
  credentialByCryptogram: async (token_ref, h) => credentials.get(`${token_ref} ${h}`),
  consume: async () => true,
};
