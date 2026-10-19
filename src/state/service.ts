// П3 Бюджет мандата на удержаниях agentic-core (РП41, PS-09 К1.2): счёт = мандат, резерв → закрепление → освобождение.
// Условие по остатку и изменение — одна операция ядра (PgHoldLedger / AsyncMemoryHoldLedger); своих реализаций и прямых
// запросов к таблицам удержаний нет (РП41 п. 2). Любое неподтверждённое состояние — STATE_UNAVAILABLE (A3 п. 4.5).
import { HoldError, type AsyncHoldLedger, type Hold, type Money } from "@kuzin4u/agentic-core";
import type { MandateStatus } from "../consent/model.js";

/** Коды П3 (РП41 п. 5): внутренние, на границе их сопоставляет вызывающий (ADP — PS-10, П10 — PS-20). */
export type StateCode =
  | "LIMIT_EXCEEDED"
  | "IDEMPOTENCY_CONFLICT"
  | "MANDATE_SCOPE"
  | "REQUEST_INVALID"
  | "MANDATE_NOT_FOUND"
  | "MANDATE_REVOKED"
  | "MANDATE_EXPIRED"
  | "PRINCIPAL_SIGNATURE_PENDING"
  | "STATE_UNAVAILABLE"
  | "RESERVATION_RELEASED"
  | "COMMIT_CONFLICT";

export type StateResult = { readonly ok: true; readonly hold: Hold } | { readonly ok: false; readonly code: StateCode };

/** Бюджет мандата из записи журнала (инвариант 5): статус свёрткой (у CART — с родителем, РП35 п. 2), предел, валюта. */
export interface MandateBudget {
  readonly status: MandateStatus;
  readonly amount_limit: number;
  readonly currency: string;
}

/** Источник бюджета — журнал согласий (П2). Неизвестный мандат — undefined; сбой или нарушенная цепочка — исключение. */
export interface MandateBudgetSource {
  budget(mandate_id: string): Promise<MandateBudget | undefined>;
}

/** Лимит клиента или инструмента — «меньшее из пределов» до резерва (A3 п. 7.2, РП41 п. 9). Подключение — PS-20. */
export interface ClientLimitCheck {
  allows(mandate_id: string, money: Money): Promise<boolean>;
}

/** До PS-20 лимит клиента не подключён: действует только предел мандата (РП41 п. 9, STATUS «Открыто» (г)). */
export const NO_CLIENT_LIMIT: ClientLimitCheck = { allows: async () => true };

export type StateLog = (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;

export interface StateServiceOptions {
  readonly reservationTtlSec: number;
  readonly now?: () => Date;
  readonly clientLimit?: ClientLimitCheck;
  readonly log?: StateLog;
}

/** Счёт удержаний мандата. Id мандата — по маске без «:», поэтому id счёта и ref однозначны. */
export const accountId = (mandate_id: string): string => `mandate:${mandate_id}`;

/** ref глобален в журнале удержаний: мандат + ключ операции (РП41 п. 4). */
export const holdRef = (mandate_id: string, op_key: string): string => `mandate:${mandate_id}:op:${op_key}`;

/** Мандат не ACTIVE — код по статусу, резерва нет (РП41 п. 5). REJECTED не стал действующим — вне пределов. */
const STATUS_CODE: Record<Exclude<MandateStatus, "ACTIVE">, StateCode> = {
  PENDING_SIGNATURE: "PRINCIPAL_SIGNATURE_PENDING",
  REVOKED: "MANDATE_REVOKED",
  EXPIRED: "MANDATE_EXPIRED",
  EXHAUSTED: "LIMIT_EXCEEDED",
  REJECTED: "MANDATE_SCOPE",
};

const fail = (code: StateCode): StateResult => ({ ok: false, code });
const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
const holdCode = (e: unknown): HoldError["code"] | undefined => (e instanceof HoldError ? e.code : undefined);

export class StateService {
  private readonly now: () => Date;
  private readonly clientLimit: ClientLimitCheck;
  private readonly log: StateLog;

  constructor(
    private readonly ledger: AsyncHoldLedger,
    private readonly source: MandateBudgetSource,
    private readonly opts: StateServiceOptions,
  ) {
    this.now = opts.now ?? (() => new Date());
    this.clientLimit = opts.clientLimit ?? NO_CLIENT_LIMIT;
    this.log = opts.log ?? (() => {});
  }

  /**
   * Открытие счёта после MANDATE_SIGNED (РП41 п. 3), идемпотентно. Сбой подпись не отменяет: счёт откроет первый резерв.
   * true — счёт есть.
   */
  async open(mandate_id: string): Promise<boolean> {
    try {
      const b = await this.source.budget(mandate_id);
      if (!b || b.status !== "ACTIVE") return false;
      await this.openFrom(mandate_id, b);
      return true;
    } catch (e) {
      this.log("warn", { mandate_id, code: holdCode(e) }, "П3: счёт мандата не открыт — откроется при первом резерве");
      return false;
    }
  }

  /**
   * Резерв (РП41 п. 4): статус по свёртке → валюта → лимит клиента → reserve ядра со сроком reservation_ttl_sec.
   * Повтор с тем же op_key, суммой и валютой — прежнее удержание. hold.id хранит вызывающий (запись операции, PS-10).
   */
  async reserve(mandate_id: string, money: Money, op_key: string): Promise<StateResult> {
    if (!isUnits(money.amount) || typeof op_key !== "string" || op_key === "") return fail("REQUEST_INVALID");
    let b: MandateBudget | undefined;
    try {
      b = await this.source.budget(mandate_id);
    } catch (e) {
      return this.unavailable(e, { mandate_id }, "П3: бюджет мандата не прочитан — резерва нет");
    }
    if (!b) return fail("MANDATE_NOT_FOUND");
    if (b.status !== "ACTIVE") return fail(STATUS_CODE[b.status]);
    if (money.currency !== b.currency) return fail("MANDATE_SCOPE");
    try {
      if (!(await this.clientLimit.allows(mandate_id, money))) return fail("LIMIT_EXCEEDED");
    } catch (e) {
      return this.unavailable(e, { mandate_id }, "П3: лимит клиента не прочитан — резерва нет");
    }
    const expires_at = this.now().getTime() + this.opts.reservationTtlSec * 1000;
    const ref = holdRef(mandate_id, op_key);
    try {
      return { ok: true, hold: await this.ledger.reserve(accountId(mandate_id), money, ref, expires_at) };
    } catch (e) {
      if (holdCode(e) !== "UNKNOWN_ACCOUNT") return this.reserveFailed(e, mandate_id);
    }
    // Счёт не открылся после подписи — открыть из записи мандата и повторить один раз (РП41 п. 3).
    try {
      await this.openFrom(mandate_id, b);
      return { ok: true, hold: await this.ledger.reserve(accountId(mandate_id), money, ref, expires_at) };
    } catch (e) {
      return this.reserveFailed(e, mandate_id);
    }
  }

  /**
   * Закрепление (РП41 п. 7): одно на удержание, всегда с освобождением остатка — commit ядра не идемпотентен.
   * Статус мандата не проверяется: резерв до отзыва исполняется (A3 п. 6.3). Повтор распознаётся по чтению удержания.
   */
  async commit(hold_id: string, money: Money): Promise<StateResult> {
    if (!isUnits(money.amount)) return fail("REQUEST_INVALID");
    try {
      return { ok: true, hold: await this.ledger.commit(hold_id, money, true) };
    } catch (e) {
      const code = holdCode(e);
      if (code === "BAD_AMOUNT" || code === "BAD_CURRENCY" || code === "CURRENCY_MISMATCH") return fail("REQUEST_INVALID");
      if (code !== "BAD_STATE") return this.unavailable(e, { hold_id }, "П3: закрепление не выполнено");
    }
    let h: Hold;
    try {
      h = await this.ledger.get(hold_id);
    } catch (e) {
      return this.unavailable(e, { hold_id }, "П3: удержание не прочитано после BAD_STATE");
    }
    if (h.committed === 0) {
      // Освобождено до клиринга (реверсал, отказ, проход expire): нового резерва в обход нет (РП41 п. 6).
      this.log("warn", { hold_id, ref: h.ref, expires_at: h.expires_at }, "П3: поздний клиринг — удержание уже освобождено");
      return fail("RESERVATION_RELEASED");
    }
    if (h.committed === money.amount && h.currency === money.currency) return { ok: true, hold: h };
    return fail("COMMIT_CONFLICT");
  }

  /** Освобождение открытой части (реверсал, отказ эмитента после ADP); идемпотентно в ядре. */
  async release(hold_id: string): Promise<StateResult> {
    try {
      return { ok: true, hold: await this.ledger.release(hold_id) };
    } catch (e) {
      return this.unavailable(e, { hold_id }, "П3: освобождение не выполнено");
    }
  }

  /** Проход срока (РП41 п. 6): освобождение истёкших резервов. Сбой — в журнал процесса, следующий проход повторит. */
  async expire(): Promise<readonly Hold[]> {
    try {
      const released = await this.ledger.expire(this.now().getTime());
      if (released.length > 0) this.log("info", { released: released.length }, "П3: истёкшие резервы освобождены");
      return released;
    } catch (e) {
      this.log("warn", { code: holdCode(e) }, "П3: проход expire не выполнен");
      return [];
    }
  }

  private async openFrom(mandate_id: string, b: MandateBudget): Promise<void> {
    await this.ledger.openAccount(accountId(mandate_id), { amount: b.amount_limit, currency: b.currency });
  }

  private reserveFailed(e: unknown, mandate_id: string): StateResult {
    switch (holdCode(e)) {
      case "INSUFFICIENT":
        return fail("LIMIT_EXCEEDED");
      case "REF_CONFLICT":
        return fail("IDEMPOTENCY_CONFLICT");
      case "CURRENCY_MISMATCH":
        return fail("MANDATE_SCOPE");
      case "BAD_AMOUNT":
      case "BAD_CURRENCY":
        return fail("REQUEST_INVALID");
      default:
        // ACCOUNT_CONFLICT — нарушение целостности; прочее — сбой хранилища или неизвестная ошибка: без догадки.
        return this.unavailable(e, { mandate_id }, "П3: резерв не выполнен");
    }
  }

  private unavailable(e: unknown, fields: Record<string, unknown>, msg: string): StateResult {
    this.log("warn", { ...fields, code: holdCode(e) ?? "storage" }, msg);
    return fail("STATE_UNAVAILABLE");
  }
}
