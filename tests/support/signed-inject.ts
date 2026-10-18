// Подписанное обращение агента к серверу через inject: подпись — agentic-core signRequest, как у клиента core.
import { randomUUID } from "node:crypto";
import { signRequest } from "@kuzin4u/agentic-core";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import type { AgentSide } from "./agent.js";

export interface SignedCall {
  method?: "GET" | "POST" | "PUT";
  path?: string;
  query?: string;
  body?: string;
  headers?: Record<string, string | null>;
  now?: Date;
}

export async function signedInject(
  app: FastifyInstance,
  side: AgentSide,
  agentCode: string,
  call: SignedCall = {},
): Promise<LightMyRequestResponse> {
  const method = call.method ?? "GET";
  const path = call.path ?? "/pao/v1/agent";
  const query = call.query ?? "";
  const body = call.body ?? "";
  const headers: Record<string, string | null> = {
    ...call.headers,
    "x-agent-code": agentCode,
    "x-timestamp": (call.now ?? new Date()).toISOString().slice(0, 19) + "Z",
    "x-nonce": randomUUID(),
  };
  // Тип содержимого вызывающего не перезаписывается; null в headers — без заголовка.
  if (body !== "" && !("content-type" in headers)) headers["content-type"] = "application/json";
  const sent = Object.fromEntries(Object.entries(headers).filter((e): e is [string, string] => e[1] !== null));
  const signed = signRequest({ method, path, query, headers: sent, body }, side.signer);
  return app.inject({
    method,
    url: query ? `${path}?${query}` : path,
    headers: signed.headers,
    ...(method === "GET" ? {} : { payload: body }),
  });
}
