// Ответы транспорта (РП62 п. 1–5): отказ до шлюза — тело ПАО §6 в области /pao, {code} вне её; каждый — запись в журнал
// процесса без пути, строки запроса и err.message (в нём путь). До ПАО 1.5.0 у 404 / 413 / 414 код тела — REQUEST_INVALID
// при HTTP Fastify (п. 2 (б), расхождение № 45); с 1.5.0 — NOT_FOUND, PAYLOAD_TOO_LARGE, URI_TOO_LONG.
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { paoError, type PaoErrorReply } from "./errors.js";

/** Предел тела в области /pao (РП62 п. 4): самое большое тело — MandateRequest с корзиной, на порядок меньше. */
export const PAO_BODY_LIMIT_BYTES = 64 * 1024;

/** Область ПАО — по сырому пути, до маршрутизации (п. 1): `/pao`, `/pao?…`, `/pao/…`. */
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

/**
 * Исключение в запись — только name, code и кадры стека (КТ1 № 8; РП62 доп. 2): перечислимые поля (у PostgreSQL — detail,
 * where) и message могут нести значения запроса, у Fastify — путь. Стек начинается строкой «Name: message» (сообщение
 * бывает многострочным), поэтому берутся только строки кадров «at …».
 */
export function errFields(err: unknown): Record<string, unknown> {
  if (!(err instanceof Error)) return { name: typeof err };
  const code = (err as { code?: unknown }).code;
  const frames = (err.stack ?? "").split("\n").filter((line) => /^\s+at /.test(line));
  return { name: err.name, ...(typeof code === "string" ? { code } : {}), stack: frames.join("\n") };
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
      ...(t.err !== undefined ? { err: errFields(t.err) } : {}),
    },
    "отказ транспорта",
  );
}

/**
 * frameworkErrors сервера (п. 1, 3): 414 FST_ERR_MAX_PARAM_LENGTH и 400 FST_ERR_BAD_URL до маршрутизации, на всём
 * сервере. Тело Fastify не отдаётся: в его message сырой путь. 5xx (FST_ERR_ASYNC_CONSTRAINT; асинхронных ограничений
 * маршрутов сейчас нет) — 503 UPSTREAM_UNAVAILABLE с Retry-After, как исключения в области (КТ1 № 4); прочие 4xx — 400.
 */
export function frameworkErrors(retryAfterSec: number) {
  return (err: { code?: string; statusCode?: number }, req: FastifyRequest, reply: FastifyReply): void => {
    const pao = isPaoPath(req.raw.url ?? "");
    const reject = err.code ?? "UNKNOWN";
    if ((err.statusCode ?? 500) >= 500) {
      const e = paoError("UPSTREAM_UNAVAILABLE");
      logTransportReject(req, { reject, status: e.http, ...(pao ? { pao_code: e.body.code } : {}) });
      void reply.code(e.http).header("retry-after", String(retryAfterSec)).send(pao ? e.body : { code: e.body.code });
      return;
    }
    const status = err.statusCode === 414 ? 414 : 400;
    const e = paoTransportError(status);
    logTransportReject(req, { reject, status, ...(pao ? { pao_code: e.body.code } : {}) });
    void reply.code(status).send(pao ? e.body : { code: "REQUEST_INVALID" });
  };
}

/**
 * Режим «только BYPASS» (РП43 п. 8; РП62 дополнение к п. 1): шлюза нет — любой путь /pao — 503 UPSTREAM_UNAVAILABLE по
 * §6 с Retry-After, как обнаружение (РП60 п. 12). Ответ — в onRequest: тело не читается (как у 404 шлюза). Без записи
 * «отказ транспорта» и без лимита, как обнаружение: режим отмечен записью «тревога» при входе. Префикс — /pao.
 */
export async function paoUnavailable(app: FastifyInstance, retryAfterSec: number): Promise<void> {
  const unavailable = (reply: FastifyReply): FastifyReply =>
    reply.code(503).header("retry-after", String(retryAfterSec)).send(paoError("UPSTREAM_UNAVAILABLE").body);
  app.addHook("onRequest", async (_req, reply) => unavailable(reply));
  app.setNotFoundHandler((_req, reply) => unavailable(reply));
}
