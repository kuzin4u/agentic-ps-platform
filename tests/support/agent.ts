// Сторона агента в тестах: пара ключей и подписант из agentic-core; kid агент вычисляет сам по RFC 7638
// из своего открытого ключа (РП23 п. 3) — без кода Платформы и без ответа реестра.
import { createHash, createPublicKey } from "node:crypto";
import { newEd25519Signer, type Signer } from "@kuzin4u/agentic-core";

/** Отпечаток JWK Ed25519 по RFC 7638: {"crv","kty","x"} по возрастанию имён, без пробелов, SHA-256, base64url. */
export function agentKid(publicKeySpkiBase64: string): string {
  const jwk = createPublicKey({ key: Buffer.from(publicKeySpkiBase64, "base64"), format: "der", type: "spki" }).export({
    format: "jwk",
  });
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)}}`;
  return createHash("sha256").update(canonical).digest("base64url");
}

export interface AgentSide {
  readonly signer: Signer;
  readonly publicKey: string;
  readonly kid: string;
}

/** Агент генерирует пару сам; закрытый ключ Платформе не передаётся (РП23 п. 2). */
export function newAgentSide(): AgentSide {
  const { signer, publicKey } = newEd25519Signer("unset");
  const kid = agentKid(publicKey);
  return { signer: { ...signer, kid }, publicKey, kid };
}

/** Заявление оператора BuyerAgent (ПС01). */
export const buyerApplication = (agent_code: string, side: AgentSide): Record<string, unknown> => ({
  agent_code,
  class: "BUYER",
  model: "buyer-agent-ref",
  runtime: "python-3.12",
  alg: "ed25519",
  public_key: side.publicKey,
});
