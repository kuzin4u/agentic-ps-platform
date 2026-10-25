// Ответы транспорта (РП62 п. 1–5): отказ до шлюза — тело ПАО §6 в области /pao, {code} вне её; каждый — запись в журнал
// процесса без пути, строки запроса и err.message (в нём путь). До ПАО 1.5.0 у 404 / 413 / 414 код тела — REQUEST_INVALID
// при HTTP Fastify (п. 2 (б), расхождение № 45); с 1.5.0 — NOT_FOUND, PAYLOAD_TOO_LARGE, URI_TOO_LONG.
import type { FastifyReply, FastifyRequest } from "fastify";
import { paoError, type PaoErrorReply } from "./errors.js";

/** Предел тела в области /pao (РП62 п. 4): самое большое тело — MandateRequest с корзиной, на порядок меньше. */
export const PAO_BODY_LIMIT_BYTES = 64 * 1024;

/** Область ПАО — по сырому пути, до маршрутизации (п. 1). */
export const isPaoPath = (rawUrl: string): boolean => /^\/pao(?:[/?]|$)/.test(rawUrl);

/** Тело §6 с REQUEST_INVALID при HTTP транспорта (п. 2 (б)); 400 — код таблицы как есть. */
export function paoTransportError(http: number): PaoErrorReply {
  return { http, body: paoError("REQUEST_INVALID").body };
}

export interface TransportReject {
  /** Код Fastify (FST_ERR_…) или NOT_FOUND; не текст ошибки. */
  readonly reject: string;
  readonly status: number;
  readonly pao_code?: string;
  /** Только исключение кода при 5xx (п. 5); ошибки Fastify сюда не передаются — в их message путь. */
  readonly err?: unknown;
}

/** Запись «отказ транспорта» (п. 5): размер запроса — длиной сырого адреса и Content-Length, без самого адреса. */
export function logTransportReject(req: FastifyRequest, t: TransportReject): void {
  const raw = req.raw.url ?? "";
  const cl = req.headers["content-length"];
  req.log.warn(
    {
      req,
      reject: t.reject,
      status: t.status,
      ...(t.pao_code !== undefined ? { pao_code: t.pao_code } : {}),
      area: isPaoPath(raw) ? "pao" : "other",
      url_length: Buffer.byteLength(raw),
      ...(typeof cl === "string" && /^\d{1,15}$/.test(cl) ? { content_length: Number(cl) } : {}),
      ...(t.err !== undefined ? { err: t.err } : {}),
    },
    "отказ транспорта",
  );
}

/**
 * frameworkErrors сервера (п. 1, 3): 414 FST_ERR_MAX_PARAM_LENGTH и 400 FST_ERR_BAD_URL до маршрутизации, на всём
 * сервере. Статус — Fastify; иное — 400 (fail-closed). Тело Fastify не отдаётся: в его message сырой путь.
 */
export function frameworkErrors(err: { code?: string; statusCode?: number }, req: FastifyRequest, reply: FastifyReply): void {
  const status = err.statusCode === 414 ? 414 : 400;
  const pao = isPaoPath(req.raw.url ?? "");
  const e = paoTransportError(status);
  logTransportReject(req, { reject: err.code ?? "UNKNOWN", status, ...(pao ? { pao_code: e.body.code } : {}) });
  void reply.code(status).send(pao ? e.body : { code: "REQUEST_INVALID" });
}
