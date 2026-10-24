// П10 Подпись HTTP-запроса участника (RFC 9421, РП36 доп. п. 2, РП46 (в)): профиль ПАО §2 с x-participant-code вместо
// x-agent-code — у чтений ПИ-8 (GET лимитов клиента). Изменяющие методы ПИ-8 — с подписью записи (РП46 (в) п. 3).
// Основа подписи — signatureBase и contentDigest ядра; verifyRequestAsync ядра требует x-agent-code в составе
// (DEFAULT_COMPONENTS), поэтому порядок проверок повторён здесь — тот же, что у ядра: состав → digest → окно → ключ →
// подпись → nonce последним (в хранилище — только nonce подписанных обращений).
import { contentDigest, signatureBase, type AsyncNonceStore } from "@kuzin4u/agentic-core";
import type { PaoRequest } from "../pao/verify.js";
import { paoNonceStore } from "../pao/stores.js";
import { ISSUER_ONLY, type ParticipantRole, type TrustedParticipants } from "./trusted.js";

/** Состав подписи запроса участника — ровно эти компоненты (порядок — как в Signature-Input). */
export const PARTICIPANT_COMPONENTS = ["@method", "@path", "@query", "content-digest", "x-participant-code", "x-timestamp", "x-nonce"] as const;

/**
 * Значение nonce участника в общем хранилище ПАО (РП30 п. 2): приставка `participant:` не совпадает ни с одним кодом
 * агента (РП21: `nspk:agent:…`), пробела нет в коде участника — разбор однозначен.
 */
export const participantNonceValue = (participant_code: string, nonce: string): string => `participant:${participant_code} ${nonce}`;

export type ParticipantAuthResult =
  | { readonly ok: true; readonly participant_code: string; readonly kid: string }
  | { readonly ok: false; readonly code: "SIGNATURE_INVALID" | "UPSTREAM_UNAVAILABLE"; readonly cause?: unknown };

export interface ParticipantVerifierOptions {
  readonly skewSec: number;
  readonly now?: () => Date;
  /** Хранилище nonce ядра — то же, что у ПАО (одна очистка); по умолчанию — память ядра (dev, стенд, тесты). */
  readonly nonces?: AsyncNonceStore;
}

const INPUT = /^sig1=\(([^)]*)\);keyid="([^"]+)";alg="([^"]+)"$/;
const SIG = /^sig1=:([A-Za-z0-9+/]+={0,2}):$/;
const invalid: ParticipantAuthResult = { ok: false, code: "SIGNATURE_INVALID" };

export class ParticipantRequestVerifier {
  private readonly now: () => Date;
  private readonly nonces: AsyncNonceStore;

  constructor(
    private readonly trusted: TrustedParticipants,
    private readonly opts: ParticipantVerifierOptions,
  ) {
    this.now = opts.now ?? (() => new Date());
    this.nonces = opts.nonces ?? paoNonceStore({ skewSec: opts.skewSec, now: () => this.now().getTime() });
  }

  /**
   * Любой отказ проверки — SIGNATURE_INVALID одним кодом (нет подписи, неизвестный участник или ключ, роль вне roles,
   * вне окна, повтор nonce); сбой хранилища nonce — UPSTREAM_UNAVAILABLE (503), не ошибка участника. roles — роли,
   * которым открыт маршрут: по умолчанию ISSUER (чтения эмитента), у маршрутов эквайрера — ACQUIRER (РП57 п. 3, 6).
   * Роль проверяется до nonce: подпись чужой роли nonce не занимает.
   */
  async verify(req: PaoRequest, roles: ReadonlySet<ParticipantRole> = ISSUER_ONLY): Promise<ParticipantAuthResult> {
    const h: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined) continue;
      // Повтор заголовка — неоднозначность, не догадка (инвариант 3).
      if (typeof value !== "string") return invalid;
      h[name.toLowerCase()] = value;
    }
    const m = INPUT.exec(h["signature-input"] ?? "");
    const s = SIG.exec(h["signature"] ?? "");
    if (!m || !s) return invalid;
    const components = m[1]!.split(" ").map((x) => x.replace(/"/g, ""));
    if (components.join(" ") !== PARTICIPANT_COMPONENTS.join(" ") || m[3] !== "ed25519") return invalid;
    const participant_code = h["x-participant-code"];
    const nonce = h["x-nonce"];
    if (!participant_code || !nonce) return invalid;
    if (h["content-digest"] !== contentDigest(req.body)) return invalid;
    const ts = Date.parse(h["x-timestamp"] ?? "");
    const inWindow = () => Number.isFinite(ts) && Math.abs(this.now().getTime() - ts) <= this.opts.skewSec * 1000;
    if (!inWindow()) return invalid;
    let base: string;
    try {
      base = signatureBase({ method: req.method, path: req.path, query: req.query, headers: h, body: req.body }, PARTICIPANT_COMPONENTS);
    } catch {
      return invalid;
    }
    if (!this.trusted.verifyRaw(participant_code, m[2]!, Buffer.from(base), Buffer.from(s[1]!, "base64"), roles)) return invalid;
    let seen: boolean;
    try {
      seen = await this.nonces.seen(participantNonceValue(participant_code, nonce));
    } catch (cause) {
      return { ok: false, code: "UPSTREAM_UNAVAILABLE", cause };
    }
    // Окно — ещё раз по свежим часам после записи nonce (как у ПАО, аудит К2.3 № 2).
    if (seen || !inWindow()) return invalid;
    return { ok: true, participant_code, kid: m[2]! };
  }
}
