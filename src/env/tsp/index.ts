// Эмулятор окружения (tsp) — SPEC §9, каноническая модель (РП6). Токен-сервис оператора (ПИ-4, РП47 п. 2–3):
// выпуск агентского токена с доменом и одноразовая криптограмма на заказ — HMAC-SHA-256 ключа эмулятора над
// canonicalJson входа. Ключ — только в памяти процесса, на диск не пишется (как РП36 п. 9); в бою — у токен-сервиса
// или банка (SEC-1). Номера карты эмулятор не знает: на входе только funding_ref банка (инвариант 1).
import { createHmac, randomBytes } from "node:crypto";
import { canonicalJson } from "@kuzin4u/agentic-core";
import { opaqueRef, type CryptogramInput, type TokenDomain, type TokenServicePort } from "../../credentials/model.js";

export const component = "env/tsp";

export interface TokenServiceEmulator extends TokenServicePort {
  /** Выпущенные токены: token_ref → funding_ref и домен (для тестов эмулятора). */
  readonly issued: ReadonlyMap<string, { readonly funding_ref: string; readonly domain: TokenDomain }>;
  /** Проверка подлинности криптограммы (ПИ-4): та же HMAC над теми же полями. */
  verify(input: CryptogramInput, cryptogram: string): boolean;
}

export function createTokenServiceEmulator(): TokenServiceEmulator {
  const key = randomBytes(32);
  const issued = new Map<string, { readonly funding_ref: string; readonly domain: TokenDomain }>();
  const mac = (input: CryptogramInput): string =>
    createHmac("sha256", key)
      .update(
        canonicalJson({
          token_ref: input.token_ref,
          order_ref: input.order_ref,
          merchant_id: input.merchant_id,
          amount_max: input.amount_max,
          currency: input.currency,
          valid_to: input.valid_to,
        }),
      )
      .digest("base64url");
  return {
    issued,
    async issueToken({ funding_ref, domain }) {
      const token_ref = opaqueRef("tok_ag_");
      issued.set(token_ref, { funding_ref, domain: structuredClone(domain) });
      return { token_ref };
    },
    async cryptogram(input) {
      if (!issued.has(input.token_ref)) throw new Error("tsp: токен не выпущен");
      return mac(input);
    },
    verify: (input, cryptogram) => issued.has(input.token_ref) && mac(input) === cryptogram,
  };
}
