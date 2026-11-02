// Вход человека в экран мандатов (UI-К2 ч. 1; решение владельца 02.11): банк, уже опознавший клиента в своём
// приложении, выдаёт одноразовую ссылку с коротким сроком; переход по ней гасит токен и открывает сессию в cookie
// `HttpOnly; Secure; SameSite=Strict` (`__Host-`: без Domain, путь /). У каждой формы — CSRF-токен сессии. Токены —
// 32 случайных байта в base64url; храним только их SHA-256, сравнение — по хэшу (значение наружу не уходит).
// Токены, cookie и CSRF в журнал не пишутся: журнал запросов — шаблон маршрута, а не путь (РП61 п. 3).
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "__Host-bank-mandates";

/** Сроки: ссылка — секунды, сессия — абсолютный срок от входа. Задаёт банк (на стенде — константы стенда). */
export interface ScreenSessionTtl {
  readonly login_ttl_sec: number;
  readonly session_ttl_sec: number;
}

export interface ScreenSession {
  readonly principal_ref: string;
  readonly csrf: string;
}

interface Pending {
  readonly principal_ref: string;
  readonly expires_ms: number;
}

interface Open {
  readonly principal_ref: string;
  readonly csrf: string;
  readonly expires_ms: number;
}

const token = (): string => randomBytes(32).toString("base64url");
const key = (t: string): string => createHash("sha256").update(t, "utf8").digest("base64url");
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

export function checkTtl(t: ScreenSessionTtl): ScreenSessionTtl {
  const ok = (n: number, max: number) => Number.isInteger(n) && n >= 1 && n <= max;
  if (!ok(t.login_ttl_sec, 600)) throw new Error("экран мандатов: срок ссылки входа — целое 1…600 с");
  if (!ok(t.session_ttl_sec, 3600)) throw new Error("экран мандатов: срок сессии — целое 1…3600 с");
  return t;
}

export class ScreenSessions {
  readonly #pending = new Map<string, Pending>();
  readonly #open = new Map<string, Open>();

  constructor(
    private readonly ttl: ScreenSessionTtl,
    private readonly now: () => Date,
  ) {
    checkTtl(ttl);
  }

  /** Токен одноразовой ссылки для уже опознанного банком клиента. */
  issueLogin(principal_ref: string): string {
    if (typeof principal_ref !== "string" || principal_ref === "") throw new Error("экран мандатов: principal_ref");
    const t = token();
    this.#pending.set(key(t), { principal_ref, expires_ms: this.now().getTime() + this.ttl.login_ttl_sec * 1000 });
    return t;
  }

  /**
   * Погашение ссылки: верный и не истёкший токен — новая сессия (id для cookie), иначе undefined. Неизвестный, погашенный
   * и истёкший — без различия. Токен гасится и при истечении.
   */
  redeemLogin(t: string): string | undefined {
    if (!TOKEN.test(t)) return undefined;
    const k = key(t);
    const p = this.#pending.get(k);
    if (!p) return undefined;
    this.#pending.delete(k);
    const at = this.now().getTime();
    if (!(at < p.expires_ms)) return undefined;
    const sid = token();
    this.#open.set(key(sid), { principal_ref: p.principal_ref, csrf: token(), expires_ms: at + this.ttl.session_ttl_sec * 1000 });
    return sid;
  }

  /** Сессия по cookie: нет, не по форме, истекла — undefined (истёкшая удаляется). */
  get(sid: string | undefined): ScreenSession | undefined {
    if (sid === undefined || !TOKEN.test(sid)) return undefined;
    const k = key(sid);
    const s = this.#open.get(k);
    if (!s) return undefined;
    if (!(this.now().getTime() < s.expires_ms)) {
      this.#open.delete(k);
      return undefined;
    }
    return { principal_ref: s.principal_ref, csrf: s.csrf };
  }

  /** CSRF формы — за постоянное время. */
  static csrfOk(s: ScreenSession, sent: unknown): boolean {
    if (typeof sent !== "string") return false;
    const a = createHash("sha256").update(s.csrf, "utf8").digest();
    const b = createHash("sha256").update(sent, "utf8").digest();
    return timingSafeEqual(a, b);
  }

  close(sid: string): void {
    if (TOKEN.test(sid)) this.#open.delete(key(sid));
  }
}

/** Значение cookie сессии из заголовка Cookie (без зависимости); не по форме — undefined. */
export function sessionCookie(header: string | undefined): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === SESSION_COOKIE) return part.slice(i + 1).trim();
  }
  return undefined;
}

export function setCookie(sid: string, maxAgeSec: number): string {
  return `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`;
}

export const CLEAR_COOKIE = `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
