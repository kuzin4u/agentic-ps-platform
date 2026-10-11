// Подписанное обращение агента к серверу через inject: подпись — agentic-core signRequest, как у клиента core.
import { randomUUID } from "node:crypto";
import { signRequest } from "@kuzin4u/agentic-core";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import type { AgentSide } from "./agent.js";

export interface SignedCall {
  method?: "GET" | "POST";
  path?: string;
  query?: string;
  body?: string;
  headers?: Record<string, string>;
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
  const headers: Record<string, string> = {
    ...call.headers,
    "x-agent-code": agentCode,
    "x-timestamp": (call.now ?? new Date()).toISOString().slice(0, 19) + "Z",
    "x-nonce": randomUUID(),
  };
  if (body !== "") headers["content-type"] = "application/json";
  const signed = signRequest({ method, path, query, headers, body }, side.signer);
  return app.inject({
    method,
    url: query ? `${path}?${query}` : path,
    headers: signed.headers,
    ...(method === "GET" ? {} : { payload: body }),
  });
}
