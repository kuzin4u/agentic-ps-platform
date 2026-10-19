// П4 Точка решения ADP (ПИ-1, SPEC §6, РП43): BYPASS первой проверкой до любого ввода-вывода, затем проверки агентской
// операции по порядку §6; первая сработавшая даёт причину. Неподтверждённое состояние — отказ, не BYPASS (РП43 п. 4).
import { createHash } from "node:crypto";
import { canonicalJson, isCurrencyCode } from "@kuzin4u/agentic-core";
import type { CanonicalMessage, Decision } from "../shared/canonical.generated.js";
import type { DecisionReason } from "../shared/codes.js";
import type { Params } from "../shared/config.js";
import type { Mandate } from "../shared/pao.js";
import type { AgentRecord } from "../registry/model.js";
import { parseAgentCode } from "../registry/code.js";
import { ConsentIntegrityError } from "../consent/model.js";
import type { StateService } from "../state/index.js";
import { STATE_TO_PI, STATUS_TO_PI } from "./codes.js";
import type { OperationRecord, OperationStore } from "./operations.js";
import {
  CLIENT_THRESHOLDS_NOT_CONNECTED,
  effectiveThreshold,
  MARKET_THRESHOLD_CURRENCY,
  parseClientThreshold,
  type ClientThresholds,
} from "./threshold.js";

/** Реестр агентов (П1): неизвестный — undefined; сбой — исключение (→ STATE_UNAVAILABLE). */
export interface AdpAgents {
  get(agent_code: string): Pick<AgentRecord, "status" | "level"> | undefined;
}

export type AdpMandate = Pick<Mandate, "status" | "type" | "parent_id" | "merchant_scope" | "currency" | "amount_limit">;

/** Журнал согласий (П2): мандат агента со статусом по свёртке; чужой или неизвестный — undefined; сбой — исключение. */
export interface AdpMandates {
  get(mandate_id: string, agent_code: string): Promise<AdpMandate | undefined>;
}

export type AdpLog = (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;

export interface AdpOptions {
  readonly agents: AdpAgents;
  readonly mandates: AdpMandates;
  readonly state: Pick<StateService, "reserve" | "release" | "hold" | "amountLeft">;
  readonly operations: OperationStore;
  readonly params: Pick<Params, "aoi_rollout_phase" | "confirm_above_kop">;
  /** Клиентский порог (ПИ-8, PS-20); не передан — не подключён, действует рыночный (РП44 п. 5). */
  readonly clientThresholds?: ClientThresholds;
  readonly log?: AdpLog;
  readonly clock?: () => number;
  readonly now?: () => Date;
}

/** Агентское сообщение некорректно (сумма, валюта, op_ref): не решение — ответ HTTP 400, у процессинга ADP_UNAVAILABLE. */
export class AdpRequestInvalid extends Error {
  constructor(readonly field: string) {
    super(`ADP: поле ${field} не по форме`);
    this.name = "AdpRequestInvalid";
  }
}

const AGENT_INSTRUMENTS: readonly string[] = ["AGENT_TOKEN", "ACCOUNT_LINK"];

/**
 * Неагентская операция ⇔ нет aoi и instrument.kind = CARD_TOKEN (ПИ-1, РП4). Только два поля сообщения: без хранилищ,
 * записи операции, идемпотентности и разбора остального тела (РП43 п. 1). aoi: null — как отсутствие признака.
 */
export function isBypass(msg: Pick<CanonicalMessage, "aoi" | "instrument">): boolean {
  return (msg.aoi === undefined || msg.aoi === null) && msg.instrument?.kind === "CARD_TOKEN";
}

/**
 * Хэш сообщения для повтора по op_ref: всё, кроме ts и seq — процессинг может переотправить ту же авторизацию с другим
 * временем; другая сумма, продавец, инструмент или признак — уже другое сообщение (РП43 п. 5).
 */
export function messageHash(msg: CanonicalMessage): string {
  const rest: Record<string, unknown> = { ...msg };
  delete rest.ts;
  delete rest.seq;
  return createHash("sha256").update(canonicalJson(rest)).digest("hex");
}

const BYPASS: Decision = Object.freeze({ decision: "BYPASS", reason: null, decided_in_ms: 0 });

/** Итог проверок агентской операции: отказ с причиной или одобрение с удержаниями. */
type Verdict =
  | { readonly reason: DecisionReason; readonly mandate_id: string | null; readonly split?: boolean }
  | {
      readonly reason: null;
      readonly mandate_id: string;
      readonly holds: readonly string[];
      readonly agent_level: number;
      readonly left?: number;
    };

const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;

export class Adp {
  private readonly log: AdpLog;
  private readonly clock: () => number;
  private readonly now: () => Date;
  /** Решения в работе по op_ref внутри процесса: одновременный повтор ждёт первое и получает его ответ. */
  private readonly inflight = new Map<string, Promise<Decision>>();

  constructor(private readonly opts: AdpOptions) {
    this.log = opts.log ?? (() => {});
    this.clock = opts.clock ?? (() => performance.now());
    this.now = opts.now ?? (() => new Date());
  }

  /** Решение по AUTH_REQUEST. Некорректное агентское сообщение — AdpRequestInvalid (не решение). */
  async decide(msg: CanonicalMessage): Promise<Decision> {
    if (isBypass(msg)) return BYPASS;
    const started = this.clock();
    const elapsed = () => Math.max(0, Math.round(this.clock() - started));
    if (typeof msg.op_ref !== "string" || msg.op_ref === "") throw new AdpRequestInvalid("op_ref");
    if (!isUnits(msg.amount)) throw new AdpRequestInvalid("amount");
    if (!isCurrencyCode(msg.currency)) throw new AdpRequestInvalid("currency");

    const running = this.inflight.get(msg.op_ref);
    if (running) {
      await running.catch(() => undefined);
      return this.decide(msg);
    }
    const p = this.decideOnce(msg, elapsed);
    this.inflight.set(msg.op_ref, p);
    try {
      return await p;
    } finally {
      this.inflight.delete(msg.op_ref);
    }
  }

  private async decideOnce(msg: CanonicalMessage, elapsed: () => number): Promise<Decision> {
    const msg_hash = messageHash(msg);
    let prior: OperationRecord | undefined;
    try {
      // Запись «в работе» до резерва (РП43 п. 5): к резерву по op_ref проходит только первый запрос.
      prior = await this.opts.operations.begin(msg.op_ref, msg_hash, this.now().toISOString());
    } catch {
      this.log("warn", { op_ref: msg.op_ref }, "ADP: запись операции не прочитана");
      return decline("STATE_UNAVAILABLE", elapsed());
    }
    if (prior) return { ...(await this.repeat(prior, msg_hash)), decided_in_ms: elapsed() };

    const v = await this.verdict(msg);
    const decision: Decision =
      v.reason === null
        ? {
            decision: "APPROVE",
            reason: null,
            reservation_id: v.holds[0] ?? null,
            agent_level: v.agent_level,
            ...(v.left === undefined ? {} : { mandate_left_after: v.left }),
            decided_in_ms: elapsed(),
          }
        : v.reason === "CONFIRMATION_REQUIRED"
          ? {
              decision: "CONFIRMATION_REQUIRED",
              reason: "CONFIRMATION_REQUIRED",
              // true — только доля (п. 9), по порогу одной операции — false (РП44 п. 7).
              split_detected: v.split === true,
              decided_in_ms: elapsed(),
            }
          : decline(v.reason, elapsed());
    try {
      await this.opts.operations.finish({
        op_ref: msg.op_ref,
        msg_hash,
        decision,
        mandate_id: v.mandate_id,
        holds: v.reason === null ? v.holds : [],
        at: this.now().toISOString(),
      });
    } catch {
      // Запись остаётся «в работе»: повтор op_ref получит STATE_UNAVAILABLE без нового резерва; решение не меняется.
      this.log("warn", { op_ref: msg.op_ref }, "ADP: запись операции не сохранена");
    }
    return decision;
  }

  /** Повтор op_ref (ПИ-1): тот же хэш — прежнее решение; у APPROVE удержание должно держать бюджет (инвариант 4). */
  private async repeat(prior: OperationRecord, msg_hash: string): Promise<Decision> {
    if (prior.msg_hash !== msg_hash) {
      this.log("warn", { op_ref: prior.op_ref, incident: true }, "ADP: повтор op_ref с другим сообщением");
      return decline("STATE_UNAVAILABLE", 0);
    }
    if (prior.decision === null) {
      // В работе на другом экземпляре или решение не сохранено: прежнего ответа нет, нового резерва не делаем.
      this.log("warn", { op_ref: prior.op_ref }, "ADP: повтор op_ref — решение ещё не записано");
      return decline("STATE_UNAVAILABLE", 0);
    }
    if (prior.decision.decision !== "APPROVE") return prior.decision;
    for (const hold_id of prior.holds) {
      const h = await this.opts.state.hold(hold_id);
      if (!h.ok) {
        this.log("warn", { op_ref: prior.op_ref, hold_id, code: h.code }, "ADP: повтор APPROVE — удержание не держит бюджет");
        return decline("STATE_UNAVAILABLE", 0);
      }
    }
    return prior.decision;
  }

  /** Проверки агентской операции по порядку SPEC §6; первая сработавшая — причина. */
  private async verdict(msg: CanonicalMessage): Promise<Verdict> {
    const kind: string | undefined = msg.instrument?.kind;
    const agentInstrument = kind !== undefined && AGENT_INSTRUMENTS.includes(kind);
    const aoi = msg.aoi ?? undefined;
    const no = (reason: DecisionReason, mandate_id: string | null = null): Verdict => ({ reason, mandate_id });

    // 1. Признак (A1 п. 3.2). Неизвестный вид инструмента без aoi — не «известно неагентская» (РП43 п. 1).
    if (aoi === undefined) {
      if (!agentInstrument) {
        this.log("warn", { op_ref: msg.op_ref, kind, incident: true }, "ADP: неизвестный вид инструмента без признака");
        return no("AOI_MISSING");
      }
      // 1а. Агентский инструмент без признака: очередь 3 — обязательный отказ (A1 п. 8.3); 1–2 — домен токена, PS-14.
      return no(this.opts.params.aoi_rollout_phase === 3 ? "AOI_MISSING" : "CREDENTIAL_INVALID");
    }
    if (aoi.indicator !== true || !wellFormedCode(aoi.agent_code)) return no("AOI_MISSING");
    const agent_code = aoi.agent_code;

    // 2, 4. Домен токена и криптограмма — PS-14; до него не подтверждено (РП43 п. 7). Неизвестный вид с aoi — реквизит
    // не опознан: CREDENTIAL_INVALID и инцидент (доп. РП43 п. 13).
    if (kind !== "CARD_TOKEN") {
      if (!agentInstrument) {
        this.log("warn", { op_ref: msg.op_ref, kind, incident: true }, "ADP: неизвестный вид инструмента при признаке");
      }
      return no("CREDENTIAL_INVALID");
    }

    // 3. Агент — из реестра (инвариант 5). Исключённый — вне реестра (A1 п. 5.3); сбой реестра — не подтверждено.
    let agent: Pick<AgentRecord, "status" | "level"> | undefined;
    try {
      agent = this.opts.agents.get(agent_code);
    } catch {
      this.log("warn", { op_ref: msg.op_ref }, "ADP: реестр агентов не прочитан");
      return no("STATE_UNAVAILABLE");
    }
    if (!agent || agent.status === "EXCLUDED") return no("AGENT_UNKNOWN");
    if (agent.status === "SUSPENDED") return no("AGENT_SUSPENDED");

    // 5. Мандат агента (чужой = неизвестный), статус — по свёртке журнала (инвариант 5).
    const mandate_id = aoi.mandate_id;
    if (typeof mandate_id !== "string" || mandate_id === "") return no("MANDATE_NOT_FOUND");
    const m = await this.mandate(mandate_id, agent_code, msg.op_ref);
    if (m === "unavailable") return no("STATE_UNAVAILABLE", mandate_id);
    if (!m) return no("MANDATE_NOT_FOUND", mandate_id);
    const statusReason = this.statusReason(m);
    if (statusReason) return no(statusReason, mandate_id);

    // 6. Продавец и валюта — в области мандата; MCC — по домену токена (PS-14).
    const merchant = msg.merchant?.id;
    if (merchant === undefined || !m.merchant_scope.includes(merchant)) return no("MANDATE_SCOPE", mandate_id);
    if (msg.currency !== m.currency) return no("MANDATE_SCOPE", mandate_id);

    // Тип мандата вне перечня (данные, а не тип) — не подтверждено, а не «как INTENT» (инвариант 3, как доп. РП43 п. 19).
    if (m.type !== "INTENT" && m.type !== "CART") return no("STATE_UNAVAILABLE", mandate_id);

    // Счета резерва: CART — свой и родителя INTENT, всегда в порядке «CART → родитель» (РП43 п. 6); INTENT — один.
    const accounts: { readonly id: string; readonly limit: number }[] = [{ id: mandate_id, limit: m.amount_limit }];
    if (m.type === "CART") {
      const parent = typeof m.parent_id === "string" && m.parent_id !== "" ? await this.mandate(m.parent_id, agent_code, msg.op_ref) : undefined;
      // CART без родителя в журнале или родитель не прочитан — не подтверждено (целостность), не APPROVE по счёту CART.
      if (parent === "unavailable" || !parent || typeof m.parent_id !== "string") return no("STATE_UNAVAILABLE", mandate_id);
      accounts.push({ id: m.parent_id, limit: parent.amount_limit });
    }

    // 10. Порог — меньшее из рыночного и клиентского (РП44 п. 5); не определён — не подтверждено. confirmation_ref до
    // PS-19 не проверяется: повтор получает тот же ответ (РП44 п. 6).
    const threshold = await this.threshold(msg, mandate_id);
    if (threshold === undefined) return no("STATE_UNAVAILABLE", mandate_id);
    if (msg.amount > threshold) return this.confirm(accounts, msg.amount, mandate_id, false);

    // 7–8, 11. Резерв: разовая сумма и остаток — одно атомарное условие ядра на каждом счёте; op_key — op_ref (РП43 п. 5).
    // Отказ на счёте родителя — освобождение резерва CART и причина родителя (РП43 п. 6).
    const money = { amount: msg.amount, currency: msg.currency };
    const holds: string[] = [];
    for (const a of accounts) {
      const r = await this.opts.state.reserve(a.id, money, msg.op_ref, { waitExhausted: false });
      if (!r.ok) {
        for (const h of holds) await this.release(h, msg.op_ref);
        const reason = STATE_TO_PI[r.code];
        if (reason === "INVALID") throw new AdpRequestInvalid("amount");
        if (r.code === "IDEMPOTENCY_CONFLICT") {
          this.log("warn", { op_ref: msg.op_ref, mandate_id: a.id, incident: true }, "ADP: резерв по op_ref с другой суммой");
        }
        if (r.code === "RESERVATION_RELEASED") {
          // Тот же ref по освобождённому удержанию: одобрить без удержания нельзя (РП41 доп. п. 19, РП43 п. 3).
          this.log("warn", { op_ref: msg.op_ref, mandate_id: a.id, incident: true }, "ADP: резерв по op_ref — удержание уже освобождено");
        }
        return no(reason, mandate_id);
      }
      holds.push(r.hold.id);
    }

    // 12. Сверка статуса после резерва (РП43 п. 5): отзыв в окне между чтением и резервом — освобождение и отказ.
    // Момент авторизации для A3 п. 6.3 — это чтение; у CART статус свёрнут с родителем (РП35 п. 2).
    const after = await this.mandate(mandate_id, agent_code, msg.op_ref);
    const late = after === "unavailable" || !after ? "STATE_UNAVAILABLE" : this.statusReason(after);
    if (late) {
      for (const h of holds) await this.release(h, msg.op_ref);
      return no(late, mandate_id);
    }
    const left = await this.leftOf(accounts);
    return {
      reason: null,
      mandate_id,
      holds,
      agent_level: agent.level,
      ...(left === undefined ? {} : { left }),
    };
  }

  /**
   * Подтверждение вместо резерва (доп. РП43 п. 15, РП44 п. 1): остаток — чтением без резерва (проверки 7–8 идут раньше);
   * меньше суммы — LIMIT_EXCEEDED, не прочитан — STATE_UNAVAILABLE.
   */
  private async confirm(accounts: readonly { readonly id: string; readonly limit: number }[], amount: number, mandate_id: string, split: boolean): Promise<Verdict> {
    const left = await this.leftOf(accounts);
    if (left === undefined) return { reason: "STATE_UNAVAILABLE", mandate_id };
    return left < amount ? { reason: "LIMIT_EXCEEDED", mandate_id } : { reason: "CONFIRMATION_REQUIRED", mandate_id, split };
  }

  /** Действующий порог в единицах валюты операции; сбой порта, ответ не по форме или другая валюта — undefined. */
  private async threshold(msg: CanonicalMessage, mandate_id: string): Promise<number | undefined> {
    let raw: unknown;
    try {
      raw = await (this.opts.clientThresholds ?? CLIENT_THRESHOLDS_NOT_CONNECTED).get(msg, mandate_id);
    } catch {
      this.log("warn", { op_ref: msg.op_ref, mandate_id }, "ADP: клиентский порог не прочитан");
      return undefined;
    }
    const client = raw === undefined ? undefined : parseClientThreshold(raw);
    if (raw !== undefined && client === undefined) {
      this.log("warn", { op_ref: msg.op_ref, mandate_id }, "ADP: клиентский порог не по форме");
      return undefined;
    }
    const market = { amount: this.opts.params.confirm_above_kop, currency: MARKET_THRESHOLD_CURRENCY };
    const t = effectiveThreshold(market, client, msg.currency);
    if (t === undefined) this.log("warn", { op_ref: msg.op_ref, mandate_id, currency: msg.currency }, "ADP: порог в валюте операции не определён");
    return t;
  }

  /** Остаток для ответа: меньшее по счетам (у CART — CART и родитель, РП43 п. 6); не прочитан хоть один — undefined. */
  private async leftOf(accounts: readonly { readonly id: string; readonly limit: number }[]): Promise<number | undefined> {
    let min: number | undefined;
    for (const a of accounts) {
      const left = await this.opts.state.amountLeft(a.id, a.limit);
      if (left === undefined) return undefined;
      min = min === undefined ? left : Math.min(min, left);
    }
    return min;
  }

  private async mandate(id: string, agent_code: string, op_ref: string): Promise<AdpMandate | undefined | "unavailable"> {
    try {
      return await this.opts.mandates.get(id, agent_code);
    } catch (e) {
      // Нарушенная цепочка — ещё и инцидент (РП43 п. 4); прочий сбой — не подтверждено.
      const incident = e instanceof ConsentIntegrityError;
      this.log("warn", { op_ref, mandate_id: id, ...(incident ? { incident: true } : {}) }, "ADP: журнал согласий не прочитан");
      return "unavailable";
    }
  }

  /** null — ACTIVE; иначе причина по статусу. Статус не определён — не подтверждено. */
  private statusReason(m: AdpMandate): DecisionReason | null {
    if (m.status === "ACTIVE") return null;
    // Статус вне перечня (данные, а не тип) — не подтверждено, а не «действует» (инвариант 3).
    return (m.status === undefined ? undefined : STATUS_TO_PI[m.status]) ?? "STATE_UNAVAILABLE";
  }

  /** Сбой освобождения отказ не меняет: удержание держит бюджет до прохода expire (безопасная сторона). */
  private async release(hold_id: string, op_ref: string): Promise<void> {
    const r = await this.opts.state.release(hold_id);
    if (!r.ok) this.log("warn", { op_ref, hold_id, code: r.code }, "ADP: удержание не освобождено — до прохода expire");
  }
}

const decline = (reason: DecisionReason, decided_in_ms: number): Decision => ({ decision: "DECLINE", reason, decided_in_ms });

function wellFormedCode(v: unknown): v is string {
  try {
    parseAgentCode(v);
    return true;
  } catch {
    return false;
  }
}
