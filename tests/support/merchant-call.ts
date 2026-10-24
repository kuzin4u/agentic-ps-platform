// Обращение агента к витрине эмулятора: подпись — agentic-core signRequest, как у агента (РП22 п. 1–2).
import { randomUUID } from "node:crypto";
import { signRequest } from "@kuzin4u/agentic-core";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import type { AgentSide } from "./agent.js";

export interface MerchantCall {
  method?: "GET" | "POST";
  path: string;
  query?: string;
  body?: unknown;
  /** Подпись ключом этого агента; без него — обращение человека (без заголовков подписи). */
  side?: AgentSide;
  agentCode?: string;
  now?: Date;
  nonce?: string;
}

/** Подписанное обращение без отправки: метод, тело, заголовки и адрес — для тестов подмены после подписи. */
export function signedMerchantRequest(c: MerchantCall) {
  const method = c.method ?? (c.body === undefined ? "GET" : "POST");
  const body = c.body === undefined ? "" : JSON.stringify(c.body);
  const query = c.query ?? "";
  let headers: Record<string, string> = body ? { "content-type": "application/json" } : {};
  if (c.side) {
    headers = {
      ...headers,
      "x-agent-code": c.agentCode ?? "",
      "x-timestamp": (c.now ?? new Date()).toISOString().slice(0, 19) + "Z",
      "x-nonce": c.nonce ?? randomUUID(),
    };
    headers = signRequest({ method, path: c.path, query, headers, body }, c.side.signer).headers;
  }
  return { method, body, headers, url: query ? `${c.path}?${query}` : c.path };
}

export async function merchantCall(app: FastifyInstance, c: MerchantCall): Promise<LightMyRequestResponse> {
  const { method, body, headers, url } = signedMerchantRequest(c);
  return app.inject({ method, url, headers, ...(body ? { payload: body } : {}) });
}

/** То же обращение по настоящему HTTP — для обрыва соединения (RESET), которого inject не показывает. */
export async function merchantFetch(base: string, c: MerchantCall): Promise<Response> {
  const { method, body, headers, url } = signedMerchantRequest(c);
  return fetch(`${base}${url}`, { method, headers, ...(body ? { body } : {}) });
}
