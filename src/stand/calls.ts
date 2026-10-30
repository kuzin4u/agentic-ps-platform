// Журнал обращений стенда (РП25 дополнение STAND-69, #69): запись на каждое обращение к приложению стенда — для тестового
// контура агента вместо его хука в stand.app после createStand. Тела не пишутся (инвариант 1): из ответа — только code
// при 4xx / 5xx. Признак source ставит стенд по типу сокета, а не по заголовкам клиента.
import { Socket } from "node:net";
import type { FastifyInstance, FastifyRequest } from "fastify";

export interface StandCall {
  readonly method: string;
  /** Путь без строки запроса. */
  readonly path: string;
  readonly status: number;
  /** Поле code тела ответа при 4xx / 5xx; тело не JSON или без code — нет. */
  readonly code?: string;
  /** keyid из Signature-Input, как прислал клиент; подпись здесь не проверяется. */
  readonly kid?: string;
  readonly nonce?: string;
  readonly idempotency_key?: string;
  /** network — по сети (сокет Node, TCP или TLS); inject — app.inject: участники самого стенда и тестовая поддержка. */
  readonly source: "network" | "inject";
}

const KEYID = /;keyid="([^"]+)"/;

const header = (req: FastifyRequest, name: string): string | undefined => {
  const v = req.headers[name];
  return typeof v === "string" && v !== "" ? v : undefined;
};

function errorCode(payload: unknown): string | undefined {
  if (typeof payload !== "string" && !Buffer.isBuffer(payload)) return undefined;
  try {
    const body: unknown = JSON.parse(payload.toString());
    const code = (body as { code?: unknown } | null)?.code;
    return typeof code === "string" ? code : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Хуки журнала — до загрузки приложения (в createStand сразу после buildServer). onSend берёт code из тела ответа,
 * onResponse пишет запись; отказы транспорта (404 / 413 / 414 Fastify) проходят те же хуки. Наружу — копия журнала.
 */
export function attachCallJournal(app: FastifyInstance): () => readonly StandCall[] {
  const calls: StandCall[] = [];
  const codes = new WeakMap<FastifyRequest, string>();
  app.addHook("onSend", async (req, reply, payload) => {
    if (reply.statusCode >= 400) {
      const code = errorCode(payload);
      if (code !== undefined) codes.set(req, code);
    }
    return payload;
  });
  app.addHook("onResponse", async (req, reply) => {
    const kid = KEYID.exec(header(req, "signature-input") ?? "")?.[1];
    const nonce = header(req, "x-nonce");
    const idempotency_key = header(req, "idempotency-key");
    const code = codes.get(req);
    calls.push(
      Object.freeze({
        method: req.method,
        path: req.url.split("?")[0] as string,
        status: reply.statusCode,
        ...(code === undefined ? {} : { code }),
        ...(kid === undefined ? {} : { kid }),
        ...(nonce === undefined ? {} : { nonce }),
        ...(idempotency_key === undefined ? {} : { idempotency_key }),
        source: req.raw.socket instanceof Socket ? "network" : "inject",
      }),
    );
  });
  return () => [...calls];
}
