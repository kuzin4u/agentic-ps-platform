// Агентский токен для тестов ADP, где реквизит — не предмет проверки (РП48 (а): CARD_TOKEN с признаком отклоняется,
// агентская операция — только AGENT_TOKEN). Домен токена — из aoi сообщения, реквизит — на продавца, сумму и валюту
// сообщения: проверки 2 и 4 проходят, остальные видят сообщение как прежде. Однократность здесь не проверяется
// (consume всегда успешен) — она в adp-credentials.test.ts и ПС05 на настоящем П5.
// Внимание: набор MCC домена строится из самих сообщений и только растёт по паре (агент, мандат) — проверку MCC (ADP п. 6,
// РП49 (д)) на этом помощнике проходит любой MCC сообщения. Отрицательные проверки MCC — только на настоящих записях токена
// (adp-credentials.test.ts; ревью ворот К2 № 3).
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
  const merchant_id = m.merchant?.id as string;
  // Наборы MCC копятся по сообщениям того же токена (параллельные сообщения с разными продавцами не затирают друг друга);
  // сообщение без MCC набор не пополняет: если у продавца уже есть набор — MANDATE_SCOPE по п. 6, как у настоящего токена;
  // если это первое сообщение продавца — набор пуст, и ADP ответит STATE_UNAVAILABLE (порча домена), а не MANDATE_SCOPE.
  const mcc = m.merchant?.mcc;
  const prior = tokens.get(token_ref)?.merchant_mcc ?? {};
  const own = Object.hasOwn(prior, merchant_id) ? (prior[merchant_id] as readonly string[]) : [];
  const set = typeof mcc === "string" && !own.includes(mcc) ? [...own, mcc] : own;
  tokens.set(token_ref, {
    token_ref,
    agent_code,
    mandate_id,
    merchant_scope: [],
    valid_to: "2099-01-01T00:00:00Z",
    funding_ref: "fnd_test",
    created_at: "2026-10-01T00:00:00Z",
    // Набор MCC — продавца и MCC сообщения: проверка MCC по домену (РП49 (д)) этим сообщениям не мешает. Отрицательные
    // проверки MCC — только на настоящих записях токена (adp-credentials.test.ts, ревью КТ1 № 4).
    merchant_mcc: Object.fromEntries([...Object.entries(prior), [merchant_id, set]]),
  });
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
