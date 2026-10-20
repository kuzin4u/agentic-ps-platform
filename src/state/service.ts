// П3 Бюджет мандата на удержаниях agentic-core (РП41, PS-09 К1.2): счёт = мандат, резерв → закрепление → освобождение.
// Условие по остатку и изменение — одна операция ядра (PgHoldLedger / AsyncMemoryHoldLedger); своих реализаций и прямых
// запросов к таблицам удержаний нет (РП41 п. 2). Любое неподтверждённое состояние — STATE_UNAVAILABLE (A3 п. 4.5).
import { HoldError, isCurrencyCode, type Account, type AsyncHoldLedger, type Hold, type Money } from "@kuzin4u/agentic-core";
import type { MandateExhaustedPayload, MandateStatus } from "../consent/model.js";

/**
 * Коды П3 (РП41 п. 5): внутренние, на границе их сопоставляет вызывающий (ADP — PS-10, П10 — PS-20).
 * Каждый — код ПАО или запись PLATFORM_DIAG (РП42 п. 3), полноту проверяет tests/unit/diag-registry.test.ts.
 */
export const STATE_CODES = [
  "LIMIT_EXCEEDED",
  "IDEMPOTENCY_CONFLICT",
  "MANDATE_SCOPE",
  "REQUEST_INVALID",
  "MANDATE_NOT_FOUND",
  "MANDATE_REVOKED",
  "MANDATE_EXPIRED",
  "PRINCIPAL_SIGNATURE_PENDING",
  "STATE_UNAVAILABLE",
  "RESERVATION_RELEASED",
  "COMMIT_CONFLICT",
] as const;
export type StateCode = (typeof STATE_CODES)[number];

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

/**
 * Счёт лимита клиента за календарный период (РП45 п. 1): клиент мандата — банк и principal_ref из журнала, предел —
 * {per_period, currency} действующей записи лимитов. «Меньшее из пределов» (A3 п. 7.2) — второй счёт удержаний ядра.
 */
export interface ClientAccount {
  readonly participant_code: string;
  readonly principal_ref: string;
  readonly period: string;
  /** Начало периода в client_limit_period_tz: DAY — YYYY-MM-DD, MONTH — YYYY-MM. */
  readonly period_start: string;
  readonly limit: Money;
}

export type StateLog = (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;

export interface StateServiceOptions {
  readonly reservationTtlSec: number;
  readonly now?: () => Date;
  readonly log?: StateLog;
  /**
   * Запись MANDATE_EXHAUSTED с событием (журнал согласий, РП41 п. 11): после закрепления всего предела и при отказе в
   * резерве, если её нет (доп. 1). Проверку «ещё ACTIVE» делает журнал под локом.
   */
  readonly exhausted?: (mandate_id: string, payload: MandateExhaustedPayload) => Promise<unknown>;
}

/** Счёт удержаний мандата. Id мандата — по маске без «:», поэтому id счёта и ref однозначны. */
const ACCOUNT_PREFIX = "mandate:";
export const accountId = (mandate_id: string): string => `${ACCOUNT_PREFIX}${mandate_id}`;

/** Мандат удержания — из id счёта; чужой счёт (не П3) — undefined. */
const mandateOf = (h: Hold): string | undefined =>
  h.account.startsWith(ACCOUNT_PREFIX) ? h.account.slice(ACCOUNT_PREFIX.length) : undefined;

/** ref глобален в журнале удержаний: мандат + ключ операции (РП41 п. 4). */
export const holdRef = (mandate_id: string, op_key: string): string => `mandate:${mandate_id}:op:${op_key}`;

/**
 * Счёт и ref лимита клиента (РП45 п. 1). В principal_ref, периоде и его начале «:» нет, поэтому разбор с конца
 * однозначен при любом participant_code.
 */
export const clientAccountId = (a: Omit<ClientAccount, "limit">): string =>
  `client:${a.participant_code}:${a.principal_ref}:${a.period}:${a.period_start}`;
export const clientHoldRef = (a: Pick<ClientAccount, "participant_code" | "principal_ref">, op_key: string): string =>
  `client:${a.participant_code}:${a.principal_ref}:op:${op_key}`;

/**
 * Мандат не ACTIVE — код по статусу, резерва нет (РП41 п. 5). REJECTED — MANDATE_REVOKED: в ПАО «отозван или отклонён»,
 * действие агента — стоп; MANDATE_SCOPE велел бы пересобрать корзину (доп. РП41 п. 5, ревью К1.2–К1.4).
 */
const STATUS_CODE: Record<Exclude<MandateStatus, "ACTIVE">, StateCode> = {
  PENDING_SIGNATURE: "PRINCIPAL_SIGNATURE_PENDING",
  REVOKED: "MANDATE_REVOKED",
  EXPIRED: "MANDATE_EXPIRED",
  EXHAUSTED: "LIMIT_EXCEEDED",
  REJECTED: "MANDATE_REVOKED",
};

const fail = (code: StateCode): StateResult => ({ ok: false, code });
const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
/**
 * Итог reserve ядра. Повтор ref отдаёт прежнее удержание в любом состоянии: освобождённое без закрепления (реверсал,
 * проход expire) бюджет не держит — RESERVATION_RELEASED, а не ok (РП41 доп. п. 19, /audit PS-09 № 1).
 */
const reserved = (hold: Hold): StateResult =>
  hold.committed === 0 && hold.released === hold.amount ? fail("RESERVATION_RELEASED") : { ok: true, hold };
/** Попытки привести предел счёта клиента к записи (РП46 (г)): гонка с резервом или открытием — перечитать. */
const CLIENT_LIMIT_ATTEMPTS = 3;
const holdCode = (e: unknown): HoldError["code"] | undefined => (e instanceof HoldError ? e.code : undefined);

export class StateService {
  private readonly now: () => Date;
  private readonly log: StateLog;

  constructor(
    private readonly ledger: AsyncHoldLedger,
    private readonly source: MandateBudgetSource,
    private readonly opts: StateServiceOptions,
  ) {
    this.now = opts.now ?? (() => new Date());
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
      if (holdCode(e) === "ACCOUNT_CONFLICT") {
        // Счёт с другим пределом — нарушение целостности, а не сбой: резервы по нему — STATE_UNAVAILABLE (РП41 п. 3).
        this.log("warn", { mandate_id, code: "ACCOUNT_CONFLICT", incident: true }, "П3: инцидент — счёт мандата с другим пределом");
        return false;
      }
      this.log("warn", { mandate_id, code: holdCode(e) }, "П3: счёт мандата не открыт — откроется при первом резерве");
      return false;
    }
  }

  /**
   * Резерв (РП41 п. 4): статус по свёртке → валюта → reserve ядра со сроком reservation_ttl_sec. Лимит клиента — свой
   * счёт, reserveClient тем же op_key после счетов мандата (РП45 п. 1).
   * Повтор с тем же op_key, суммой и валютой — прежнее удержание. hold.id хранит вызывающий (запись операции, РП43 п. 5).
   * waitExhausted: false — путь ADP: дописывание MANDATE_EXHAUSTED при INSUFFICIENT без ожидания лока журнала (РП43 п. 9).
   */
  async reserve(
    mandate_id: string,
    money: Money,
    op_key: string,
    opts: { readonly waitExhausted?: boolean } = {},
  ): Promise<StateResult> {
    if (!isUnits(money.amount) || !isCurrencyCode(money.currency) || typeof op_key !== "string" || op_key === "") {
      return fail("REQUEST_INVALID");
    }
    let b: MandateBudget | undefined;
    try {
      b = await this.source.budget(mandate_id);
    } catch (e) {
      return this.unavailable(e, { mandate_id }, "П3: бюджет мандата не прочитан — резерва нет");
    }
    if (!b) return fail("MANDATE_NOT_FOUND");
    // Статус вне перечня (данные, а не тип) — не подтверждено (инвариант 3), а не пара без кода.
    if (b.status !== "ACTIVE") return fail(STATUS_CODE[b.status] ?? "STATE_UNAVAILABLE");
    if (money.currency !== b.currency) return fail("MANDATE_SCOPE");
    const expires_at = this.now().getTime() + this.opts.reservationTtlSec * 1000;
    const ref = holdRef(mandate_id, op_key);
    try {
      return reserved(await this.ledger.reserve(accountId(mandate_id), money, ref, expires_at));
    } catch (e) {
      // Предел закреплён целиком, а записи нет (сбой после commit) — дописать; ответ тот же (доп. 1 к РП41 п. 11).
      if (holdCode(e) === "INSUFFICIENT") {
        const marking = this.markExhausted(mandate_id);
        if (opts.waitExhausted !== false) await marking;
      }
      if (holdCode(e) !== "UNKNOWN_ACCOUNT") return this.reserveFailed(e, { mandate_id });
    }
    // Счёт не открылся после подписи — открыть из записи мандата и повторить один раз (РП41 п. 3).
    try {
      await this.openFrom(mandate_id, b);
      return reserved(await this.ledger.reserve(accountId(mandate_id), money, ref, expires_at));
    } catch (e) {
      return this.reserveFailed(e, { mandate_id });
    }
  }

  /**
   * Резерв лимита клиента за период (РП45 п. 1): второй счёт удержаний ядра, условие по остатку и изменение — одна
   * операция ядра, поэтому и на двух экземплярах сумма одобрений по всем мандатам клиента не выше предела (инвариант 4).
   * Предел счёта приводится к действующей записи лимитов до резерва (applyClientLimit, РП46 (г)).
   */
  async reserveClient(a: ClientAccount, money: Money, op_key: string): Promise<StateResult> {
    if (!isUnits(money.amount) || !isCurrencyCode(money.currency) || typeof op_key !== "string" || op_key === "") {
      return fail("REQUEST_INVALID");
    }
    const fields = { participant_code: a.participant_code, principal_ref: a.principal_ref, period_start: a.period_start };
    // Валюта записи лимитов ≠ валюте операции — не подтверждено, а не «лимита нет» (РП45 п. 1).
    if (a.limit.currency !== money.currency) return this.unavailable(undefined, fields, "П3: валюта лимита клиента ≠ валюте операции");
    if (a.limit.amount === 0) return fail("LIMIT_EXCEEDED");
    const id = clientAccountId(a);
    const applied = await this.applyClientLimit(id, a.limit, fields);
    if (applied) return applied;
    const expires_at = this.now().getTime() + this.opts.reservationTtlSec * 1000;
    try {
      return reserved(await this.ledger.reserve(id, money, clientHoldRef(a, op_key), expires_at));
    } catch (e) {
      return this.reserveFailed(e, fields);
    }
  }

  /**
   * Предел счёта клиента — по действующей записи (РП46 (г)): сначала account, setLimit — только при расхождении (обычный
   * путь — account и reserve). Расширение и сужение — сразу; запись ниже использованного — предел committed + reserved
   * (остаток 0, резерв — LIMIT_EXCEEDED), а уже суженный до использованного счёт setLimit не вызывает. После освобождения
   * удержаний предел снова приводится к записи — освобождённое запись не превышает. LIMIT_BELOW_USED (между чтением и
   * setLimit прошёл резерв) и ACCOUNT_CONFLICT открытия (счёт открыл другой экземпляр) — перечитать, не больше трёх раз.
   */
  private async applyClientLimit(id: string, limit: Money, fields: Record<string, unknown>): Promise<StateResult | undefined> {
    for (let attempt = 0; attempt < CLIENT_LIMIT_ATTEMPTS; attempt++) {
      let acc: Account;
      try {
        acc = await this.ledger.account(id);
      } catch (e) {
        if (holdCode(e) !== "UNKNOWN_ACCOUNT") return this.unavailable(e, fields, "П3: счёт лимита клиента не прочитан — резерва нет");
        try {
          await this.ledger.openAccount(id, limit);
          return undefined;
        } catch (e2) {
          if (holdCode(e2) === "ACCOUNT_CONFLICT") continue;
          return this.unavailable(e2, fields, "П3: счёт лимита клиента не открыт — резерва нет");
        }
      }
      // Смена валюты лимита в периоде — со следующего периода (РП45 доп. п. 7): здесь не ожидается — не подтверждено.
      if (acc.currency !== limit.currency) {
        return this.unavailable(undefined, { ...fields, currency: acc.currency }, "П3: валюта счёта клиента ≠ валюте записи лимитов");
      }
      const target = Math.max(limit.amount, acc.committed + acc.reserved);
      if (acc.limit === target) return undefined;
      try {
        await this.ledger.setLimit(id, { amount: target, currency: limit.currency });
        return undefined;
      } catch (e) {
        if (holdCode(e) !== "LIMIT_BELOW_USED") return this.unavailable(e, fields, "П3: предел счёта клиента не изменён — резерва нет");
      }
    }
    return this.unavailable(undefined, fields, "П3: предел счёта клиента не приведён к записи за три попытки — резерва нет");
  }

  /**
   * Остаток лимита клиента за период для ответа без резерва (подтверждение, РП44 п. 1) — по записи, а не по пределу
   * счёта: max(0, предел записи − committed − reserved) (РП46 (г) п. 3). Счёта ещё нет — предел; сбой, другая валюта
   * счёта — undefined (не подтверждено).
   */
  async clientLeft(a: ClientAccount): Promise<number | undefined> {
    if (a.limit.amount === 0) return 0;
    try {
      const acc = await this.ledger.account(clientAccountId(a));
      if (acc.currency !== a.limit.currency) return undefined;
      return Math.max(0, a.limit.amount - acc.committed - acc.reserved);
    } catch (e) {
      if (holdCode(e) === "UNKNOWN_ACCOUNT") return a.limit.amount;
      this.log("warn", { principal_ref: a.principal_ref, code: holdCode(e) ?? "storage" }, "П3: остаток лимита клиента не прочитан");
      return undefined;
    }
  }


  /**
   * Закрепление (РП41 п. 7): одно на удержание, всегда с освобождением остатка — commit ядра не идемпотентен.
   * Статус мандата не проверяется: резерв до отзыва исполняется (A3 п. 6.3). Повтор распознаётся по чтению удержания.
   */
  async commit(hold_id: string, money: Money): Promise<StateResult> {
    if (!isUnits(money.amount)) return fail("REQUEST_INVALID");
    try {
      const hold = await this.ledger.commit(hold_id, money, true);
      await this.markExhausted(mandateOf(hold));
      return { ok: true, hold };
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
    if (h.committed === money.amount && h.currency === money.currency) {
      // Повтор закрепления дописывает исчерпание, если первый вызов упал между commit и записью (РП41 п. 11).
      await this.markExhausted(mandateOf(h));
      return { ok: true, hold: h };
    }
    return fail("COMMIT_CONFLICT");
  }

  /**
   * Удержание по hold_id — для повтора решения ADP по op_ref (РП43 п. 5): освобождённое без закрепления бюджет не держит —
   * RESERVATION_RELEASED (как РП41 доп. п. 19); неизвестное или сбой чтения — STATE_UNAVAILABLE (доп. п. 15).
   */
  async hold(hold_id: string): Promise<StateResult> {
    try {
      return reserved(await this.ledger.get(hold_id));
    } catch (e) {
      return this.unavailable(e, { hold_id }, "П3: удержание не прочитано");
    }
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

  /**
   * Остаток для verify (РП41 п. 10): available счёта, не ниже 0; счёта ещё нет — предел (расходования не было, чтение
   * счёт не открывает); сбой — undefined (STATE_UNKNOWN).
   */
  async amountLeft(mandate_id: string, amount_limit: number): Promise<number | undefined> {
    try {
      return Math.max(0, (await this.ledger.available(accountId(mandate_id))).amount);
    } catch (e) {
      if (holdCode(e) === "UNKNOWN_ACCOUNT") return amount_limit;
      this.log("warn", { mandate_id, code: holdCode(e) ?? "storage" }, "П3: остаток не прочитан — STATE_UNKNOWN");
      return undefined;
    }
  }

  /** Закреплён весь предел — запись MANDATE_EXHAUSTED (РП41 п. 11). Сбой — в журнал процесса, ответ П3 не меняется. */
  private async markExhausted(mandate_id: string | undefined): Promise<void> {
    if (!mandate_id || !this.opts.exhausted) return;
    try {
      const a = await this.ledger.account(accountId(mandate_id));
      if (a.committed < a.limit) return;
      await this.opts.exhausted(mandate_id, { committed: a.committed, currency: a.currency });
    } catch (e) {
      this.log("warn", { mandate_id, code: holdCode(e) ?? "storage" }, "П3: запись MANDATE_EXHAUSTED не выполнена");
    }
  }

  private async openFrom(mandate_id: string, b: MandateBudget): Promise<void> {
    await this.ledger.openAccount(accountId(mandate_id), { amount: b.amount_limit, currency: b.currency });
  }

  private reserveFailed(e: unknown, fields: Record<string, unknown>): StateResult {
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
      case "ACCOUNT_CONFLICT":
      case "LIMIT_BELOW_USED":
        // Нарушение целостности (резерв не меняет предел — LIMIT_BELOW_USED здесь не ожидается, ядро v0.11.0): без догадки.
        return this.unavailable(e, fields, "П3: резерв не выполнен — нарушение целостности счёта");
      default:
        // Сбой хранилища или неизвестная ошибка: без догадки.
        return this.unavailable(e, fields, "П3: резерв не выполнен");
    }
  }

  private unavailable(e: unknown, fields: Record<string, unknown>, msg: string): StateResult {
    this.log("warn", { ...fields, code: holdCode(e) ?? "storage" }, msg);
    return fail("STATE_UNAVAILABLE");
  }
}
