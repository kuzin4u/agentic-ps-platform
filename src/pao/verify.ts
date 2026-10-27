// П9 Проверка обращения ПАО (ПАО §2, A2 п. 5, РП23 п. 6): [сертификат канала — РП66, если mtls] → агент в реестре →
// подпись → статус агента.
// Подпись проверяет agentic-core verifyRequestAsync — тот же код, которым подписывает агент (совместный тест С0).
// Ключ ищется только среди ключей агента из x-agent-code: иначе агент A подписывал бы за агента B (инвариант 5).
// Nonce — хранилище ядра, проверка и запись одной командой после верной подписи (РП30 п. 1–2, Ш3а).
import { createHash } from "node:crypto";
import { ed25519Verifier, verifyRequestAsync, type AsyncNonceStore, type Verifier } from "@kuzin4u/agentic-core";
import type { KeyForVerify } from "../registry/agent-keys.js";
import type { AgentRecord } from "../registry/model.js";
import { checkChannel, type ChannelOptions, type ChannelReject } from "./channel.js";
import { paoNonceStore } from "./stores.js";

/** Обращение в том виде, в каком оно пришло: путь и запрос — без декодирования, тело — строкой, без тела — "" (РП16). */
export interface PaoRequest {
  readonly method: string;
  readonly path: string;
  readonly query: string;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly body: string;
  /**
   * У метода без тела (GET, DELETE, HEAD) пришло тело — Content-Length не 0 или Transfer-Encoding (РП62 п. 7): подпись
   * проверялась бы по digest пустого тела, а тело другое — SIGNATURE_INVALID.
   */
  readonly unexpectedBody?: boolean;
  /** Сертификат клиента из TLS-соединения, DER; без TLS или без сертификата — нет (ступень 0, РП66 п. 1). */
  readonly clientCertificate?: Buffer;
}

/**
 * Подписываемые заголовки (ПАО §2): повтор любого — неоднозначность (РП62 п. 6). Node склеивает повтор через «, », поэтому
 * вызывающий передаёт такой заголовок массивом из headersDistinct, а verify отвечает SIGNATURE_INVALID.
 */
export const SIGNED_HEADERS = ["x-agent-code", "x-timestamp", "x-nonce", "content-digest", "signature", "signature-input"] as const;

export type PaoAuthError =
  | "AGENT_UNKNOWN"
  | "SIGNATURE_INVALID"
  | "AGENT_KEY_REVOKED"
  | "AGENT_SUSPENDED"
  | "UPSTREAM_UNAVAILABLE";

export type PaoAuthResult =
  | { readonly ok: true; readonly agent: AgentRecord; readonly kid: string }
  | {
      readonly ok: false;
      readonly code: PaoAuthError;
      readonly norm?: string;
      /** Исключение источника — для журнала процесса Платформы; агенту не передаётся. */
      readonly cause?: unknown;
      /** Вид причины отказа ступени 0 — для журнала процесса; агенту — только AGENT_UNKNOWN (РП66 п. 2). */
      readonly channel?: ChannelReject;
    };

/** Сбой реестра или ключей — не ошибка агента: 503 UPSTREAM_UNAVAILABLE, same_key (ПАО §6; РП23 п. 6; аудит PS-04 №2). */
const upstreamFail = (cause: unknown): Extract<PaoAuthResult, { ok: false }> => ({ ok: false, code: "UPSTREAM_UNAVAILABLE", cause });
const upstream = (cause: unknown): PaoAuthResult => upstreamFail(cause);

/** Реестр и ключи в той мере, в какой они нужны проверке (П1); чтение — из хранилища на каждом обращении (РП64 п. 3). */
export interface PaoAuthSources {
  getAgent(agent_code: string): Promise<AgentRecord | undefined>;
  lookupKey(agent_code: string, kid: string): Promise<KeyForVerify | undefined>;
}

/**
 * Значение nonce в общей области `pao` (РП30 п. 2; РП62 п. 11): код агента, пробел, SHA-256 от x-nonce в base64url. Длина
 * не зависит от x-nonce: сырой x-nonce до 16 КБ заголовков не помещался в индекс core_nonces — ошибка агента становилась
 * 503 Платформы. Пробела нет в грамматике кода агента (РП21), разбор по первому пробелу однозначен. Пустой x-nonce сюда
 * не попадает (см. verify). Смена вида значения — развёртывание с остановкой не короче 2 × signature_skew_sec (нюанс 3).
 */
export const nonceValue = (agent_code: string, nonce: string): string =>
  `${agent_code} ${createHash("sha256").update(nonce, "utf8").digest("base64url")}`;

/** Метод, доступный приостановленному и исключённому агенту: узнать свой статус (РП23 п. 6.3). */
const STATUS_EXEMPT = new Set(["GET /pao/v1/agent"]);

/**
 * Методы, доступные и приостановленному: только снимают полномочия, расширить их нельзя. Отказ от полномочий
 * (решение владельца 19.10.2026, #33; РП38 доп. п. 8) и отзыв своего ключа (РП60 п. 3). Исключённому — нет.
 * Регистрация ключа приостановленным — 403 (РП23 п. 6.3, доп. 8).
 */
const SUSPENDED_ALLOWED: readonly RegExp[] = [
  /^\/pao\/v1\/mandates\/[^/]+\/relinquish$/,
  /^\/pao\/v1\/agent\/keys\/[^/]+\/revoke$/,
];

const statusAllows = (status: AgentRecord["status"], method: string, path: string): boolean =>
  status === "ACTIVE" ||
  STATUS_EXEMPT.has(`${method} ${path}`) ||
  (status === "SUSPENDED" && method === "POST" && SUSPENDED_ALLOWED.some((p) => p.test(path)));

export interface PaoVerifierOptions {
  readonly skewSec: number;
  readonly now?: () => Date;
  /** Хранилище nonce ядра (РП30); по умолчанию — память ядра со сроком 2 × skewSec (dev, стенд, тесты). */
  readonly nonces?: AsyncNonceStore;
  /** Проверка подписи по алгоритму ключа — точка расширения РП5; по умолчанию ed25519. */
  readonly verifier?: Verifier;
  /** Ступень 0 — сертификат канала (песочница с mTLS, РП66 п. 1); без неё — стенд и dev (РП27 п. 5). */
  readonly mtls?: ChannelOptions;
}

export class PaoRequestVerifier {
  private readonly now: () => Date;
  readonly nonces: AsyncNonceStore;
  private readonly verifier: Verifier;

  constructor(
    private readonly sources: PaoAuthSources,
    private readonly opts: PaoVerifierOptions,
  ) {
    this.now = opts.now ?? (() => new Date());
    this.nonces = opts.nonces ?? paoNonceStore({ skewSec: opts.skewSec, now: () => this.now().getTime() });
    this.verifier = opts.verifier ?? ed25519Verifier;
  }

  /**
   * Порядок РП23 п. 6: AGENT_UNKNOWN → SIGNATURE_INVALID / AGENT_KEY_REVOKED → AGENT_SUSPENDED. Любой сбой — отказ:
   * сбой источника (реестр, ключи, хранилище nonce — РП30 п. 1) — UPSTREAM_UNAVAILABLE, прочие исключения проверки —
   * SIGNATURE_INVALID.
   */
  /**
   * Проверки до тела (РП63 п. 9): повтор заголовка, агент в реестре, тело у метода без тела — в onRequest, тело обращения
   * неизвестного агента не читается. Тот же порядок и коды, что в начале verify; verify повторяет их сам.
   */
  async precheck(req: Omit<PaoRequest, "body">): Promise<Extract<PaoAuthResult, { ok: false }> | undefined> {
    const r = await this.head(req);
    return "agent" in r ? undefined : r;
  }

  private async head(
    req: Omit<PaoRequest, "body">,
  ): Promise<Extract<PaoAuthResult, { ok: false }> | { readonly agent: AgentRecord; readonly headers: Record<string, string> }> {
    // Ступень 0 — до РП23 п. 6.1 и до разбора заголовков (РП27 п. 3, РП66 п. 1): повтор x-agent-code — несовпадение кода.
    if (this.opts.mtls) {
      let ch: Awaited<ReturnType<typeof checkChannel>>;
      try {
        ch = await checkChannel(req.clientCertificate, req.headers["x-agent-code"], this.now(), this.opts.mtls);
      } catch {
        // Исключение проверки (не чтения реестра — то UPSTREAM внутри checkChannel) — отказ по §6, а не 500 (КТ1 № 4).
        ch = { ok: false, reject: "CHECK_FAILED" };
      }
      if (!ch.ok) return "cause" in ch ? upstreamFail(ch.cause) : { ok: false, code: "AGENT_UNKNOWN", norm: "A2 п. 5.1", channel: ch.reject };
    }

    // Повтор заголовка — неоднозначность, не догадка (инвариант 3).
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined) continue;
      if (typeof value !== "string") return fail("SIGNATURE_INVALID");
      headers[name.toLowerCase()] = value;
    }

    const agentCode = headers["x-agent-code"];
    let agent: AgentRecord | undefined;
    try {
      agent = agentCode ? await this.sources.getAgent(agentCode) : undefined;
    } catch (e) {
      return upstreamFail(e);
    }
    if (!agentCode || !agent) return { ok: false, code: "AGENT_UNKNOWN", norm: "A2 п. 5.1" };
    if (req.unexpectedBody) return fail("SIGNATURE_INVALID");
    return { agent, headers };
  }

  async verify(req: PaoRequest): Promise<PaoAuthResult> {
    const h = await this.head(req);
    if (!("agent" in h)) return h;
    const { agent, headers } = h;

    const now = this.now().getTime();
    // Алгоритм подписи — атрибут ключа (РП5): alg из Signature-Input должен совпасть с alg ключа.
    let keyAlg: string | undefined;
    let sourceFailure: { readonly cause: unknown } | undefined;
    const lookupKey = async (kid: string): Promise<KeyForVerify | undefined> => {
      let key: KeyForVerify | undefined;
      try {
        key = await this.sources.lookupKey(agent.agent_code, kid);
      } catch (e) {
        sourceFailure = { cause: e };
        throw e;
      }
      keyAlg = key?.alg;
      return key;
    };
    const verifier: Verifier = {
      verify: (alg, publicKey, data, sig) => alg === keyAlg && this.verifier.verify(alg, publicKey, data, sig),
    };

    // Ядро вызывает seenNonce только после верной подписи (РП23 п. 6.2, Ш4): проверка и запись — одна команда.
    // После записи окно проверяется ещё раз по свежим часам (аудит К2.3 №2): ядро сверило окно до поиска ключа,
    // подписи и ожидания пула, а очистка вправе удалить строку nonce через 2 × skew после её записи. Повтор, прошедший
    // окно на самом краю, мог бы вставиться уже после такой очистки; по свежим часам он вне окна — отказ.
    const ts = Date.parse(headers["x-timestamp"] ?? "");
    const seenNonce = async (n: string): Promise<boolean> => {
      if (n === "") return true;
      let seen: boolean;
      try {
        seen = await this.nonces.seen(nonceValue(agent.agent_code, n));
      } catch (e) {
        sourceFailure = { cause: e };
        throw e;
      }
      return seen || !(Math.abs(this.now().getTime() - ts) <= this.opts.skewSec * 1000);
    };

    let result: Awaited<ReturnType<typeof verifyRequestAsync>>;
    try {
      result = await verifyRequestAsync(
        { method: req.method, path: req.path, query: req.query, headers, body: req.body },
        lookupKey,
        { now, skewSec: this.opts.skewSec, seenNonce, verifier },
      );
    } catch {
      return sourceFailure ? upstream(sourceFailure.cause) : fail("SIGNATURE_INVALID");
    }
    // Сбой источника — UPSTREAM и тогда, когда core перехватит исключение сам и вернёт отказ (повторный аудит №3).
    if (sourceFailure) return upstream(sourceFailure.cause);
    if (!result.ok) return fail(result.code);

    if (!statusAllows(agent.status, req.method.toUpperCase(), req.path)) {
      return { ok: false, code: "AGENT_SUSPENDED", norm: "A2 п. 7.1" };
    }
    return { ok: true, agent, kid: result.kid };
  }
}

const fail = (code: "SIGNATURE_INVALID" | "AGENT_KEY_REVOKED"): Extract<PaoAuthResult, { ok: false }> => ({
  ok: false,
  code,
  norm: code === "AGENT_KEY_REVOKED" ? "A2 п. 5.4" : "A2 п. 5.1",
});
