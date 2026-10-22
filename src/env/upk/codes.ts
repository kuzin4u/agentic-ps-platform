// Одноразовый код страницы УПК (РП51 п. 15, «Дополнения» п. 8): вход человека на стенде. Код выдаёт эмулятор эмитента
// вне ПАО (человек получил его в банке; в бою — 3-D Secure или приложение банка, ПИ-6); агенту он недоступен (инвариант 7).
// Код привязан к одному confirmation_id и истекает вместе с запросом; верный ввод гасит код, 3 неверных — сжигают;
// сравнение — за постоянное время; причина отказа наружу не отдаётся.
import { createHash, randomInt, timingSafeEqual } from "node:crypto";

/** Неверных вводов до сгорания кода (решение владельца 22.10). */
export const UPK_CODE_MAX_ATTEMPTS = 3;

interface Entry {
  readonly digest: Buffer;
  readonly expires_at: string;
  attempts: number;
  /** Погашен верным вводом или сожжён неверными. */
  spent: boolean;
}

const digest = (code: string): Buffer => createHash("sha256").update(code, "utf8").digest();

export class UpkCodes {
  readonly #codes = new Map<string, Entry>();

  /** Новый код запроса (6 цифр); прежний код этого запроса больше не действует. */
  issue(confirmation_id: string, expires_at: string): string {
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    this.#codes.set(confirmation_id, { digest: digest(code), expires_at, attempts: 0, spent: false });
    return code;
  }

  /**
   * Проверка и погашение: true — код верный, действует и теперь погашен. Неверный, сгоревший, погашенный, чужой и
   * истёкший — false, без различия (наружу — один ответ). Неверный ввод считается и у действующего кода.
   */
  redeem(confirmation_id: string, code: string, now: string): boolean {
    const e = this.#codes.get(confirmation_id);
    // Сравнение — всегда, и при отсутствии кода: время ответа не выдаёт, есть ли код у запроса.
    const ok = timingSafeEqual(digest(code), e?.digest ?? digest(""));
    if (!e || e.spent || !(now < e.expires_at)) return false;
    if (!ok) {
      e.attempts += 1;
      if (e.attempts >= UPK_CODE_MAX_ATTEMPTS) e.spent = true;
      return false;
    }
    e.spent = true;
    return true;
  }
}
