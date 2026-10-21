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
import { sha256Hex, type CredentialRecord, type TokenRecord } from "../credentials/model.js";
import type { CredentialStore } from "../credentials/store.js";
import type { StateService } from "../state/index.js";
import { STATE_TO_PI, STATUS_TO_PI } from "./codes.js";
import type { LimitSource, OperationNotify, OperationRecord, OperationStore, WindowResult } from "./operations.js";
import {
  effectivePeriodLimit,
  parseLimits,
  periodStart,
  type ClientLimits,
  type ClientRef,
  type PeriodLimit,
} from "../participants/limits.js";
import { clientAccountId, type ClientAccount } from "../state/index.js";
import {
  clientThreshold,
  effectiveThreshold,
  MARKET_THRESHOLD_CURRENCY,
  parseClientThreshold,
  type ClientLimitsSource,
} from "./threshold.js";

/** Реестр агентов (П1): неизвестный — undefined; сбой — исключение (→ STATE_UNAVAILABLE). */
export interface AdpAgents {
  get(agent_code: string): Pick<AgentRecord, "status" | "level"> | undefined;
}

export type AdpMandate = Pick<Mandate, "status" | "type" | "parent_id" | "merchant_scope" | "currency" | "amount_limit"> & {
  /** Клиент мандата из журнала (РП45 п. 1): банк подписи корня и principal_ref; null — подписи корня нет. */
  readonly client: ClientRef | null;
};

/** Журнал согласий (П2): мандат агента со статусом по свёртке; чужой или неизвестный — undefined; сбой — исключение. */
export interface AdpMandates {
  get(mandate_id: string, agent_code: string): Promise<AdpMandate | undefined>;
}

/**
 * Агентские реквизиты (П5, РП47 п. 6–8): домен токена (п. 2), запись реквизита по криптограмме (п. 4), погашение после
 * резерва. Не подключены — AGENT_TOKEN не подтверждается: CREDENTIAL_INVALID, как до PS-14 (РП43 п. 7). Сбой — исключение.
 */
export type AdpCredentials = Pick<CredentialStore, "tokenByRef" | "credentialByCryptogram" | "consume">;

export type AdpLog = (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;

export interface AdpOptions {
  readonly agents: AdpAgents;
  readonly mandates: AdpMandates;
  readonly state: Pick<StateService, "reserve" | "reserveClient" | "release" | "hold" | "amountLeft" | "clientLeft">;
  readonly operations: OperationStore;
  readonly params: Pick<
    Params,
    "aoi_rollout_phase" | "confirm_above_kop" | "split_window_sec" | "split_min_ops" | "client_limit_period_tz"
  >;
  /**
   * Лимиты клиента (ПИ-8, РП45 п. 1–2) — обязательны (решение владельца по /audit): забытый порт — ошибка сборки, а не
   * «проверки нет». У мандата без клиента (подписи корня нет) — STATE_UNAVAILABLE.
   */
  readonly clientLimits: ClientLimitsSource;
  readonly credentials?: AdpCredentials;
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
 * Неагентская операция ⇔ instrument.kind = CARD_TOKEN и признака нет (ПИ-1, РП4). Только два поля сообщения: без
 * хранилищ, записи операции, идемпотентности и разбора остального тела (РП43 п. 1). aoi: null — как отсутствие признака;
 * aoi.indicator === false без кода агента и мандата (нет или null) — тоже (РП49 (в)): эквайрер может передавать поле
 * признака во всех сообщениях. false с кодом агента или мандатом — противоречивый признак, агентская.
 */
export function isBypass(msg: Pick<CanonicalMessage, "aoi" | "instrument">): boolean {
  if (msg.instrument?.kind !== "CARD_TOKEN") return false;
  const aoi = msg.aoi;
  if (aoi === undefined || aoi === null) return true;
  return aoi.indicator === false && (aoi.agent_code === undefined || aoi.agent_code === null) && (aoi.mandate_id === undefined || aoi.mandate_id === null);
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

/**
 * Итог проверок агентской операции: отказ с причиной или одобрение с удержаниями. notify — признаки для уведомителя
 * участника (РП46 доп. п. 9 (о1)), когда клиент мандата известен.
 */
type Verdict =
  | { readonly reason: DecisionReason; readonly mandate_id: string | null; readonly split?: boolean; readonly notify?: OperationNotify }
  | {
      readonly reason: null;
      readonly mandate_id: string;
      readonly holds: readonly string[];
      readonly agent_level: number;
      readonly left?: number;
      readonly notify?: OperationNotify;
    };

type Declined = Extract<Verdict, { readonly reason: DecisionReason }>;

/** Остаток по счетам мандата и, если есть лимит клиента за период, по счёту клиента. */
interface Left {
  readonly mandate: number;
  readonly client?: number;
}

const minLeft = (l: Left): number => (l.client === undefined ? l.mandate : Math.min(l.mandate, l.client));

const isUnits = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;

export class Adp {
  private readonly log: AdpLog;
  private readonly clock: () => number;
  private readonly now: () => Date;
  /** Решения в работе по op_ref внутри процесса: одновременный повтор ждёт первое и получает его ответ. */
  private readonly inflight = new Map<string, Promise<Decision>>();
  /** Инциденты «CARD_TOKEN с признаком» по паре эквайрер + продавец (РП48 (а)): в памяти процесса, с перезапуском — с нуля. */
  private readonly cardTokenAoi = new Map<string, number>();

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
        ...(v.notify ? { notify: v.notify } : {}),
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
    // Признаки уведомителя — с момента, когда известен клиент мандата; чей предел — только у LIMIT_EXCEEDED.
    let notify: OperationNotify | undefined;
    const no = (reason: DecisionReason, mandate_id: string | null = null, source?: LimitSource): Declined => ({
      reason,
      mandate_id,
      ...(notify ? { notify: reason === "LIMIT_EXCEEDED" && source ? { ...notify, limit_source: source } : notify } : {}),
    });

    // 1. Признак (A1 п. 3.2). Неизвестный вид инструмента без aoi — не «известно неагентская» (РП43 п. 1).
    if (aoi === undefined) {
      if (!agentInstrument) {
        this.log("warn", { op_ref: msg.op_ref, kind, incident: true }, "ADP: неизвестный вид инструмента без признака");
        return no("AOI_MISSING");
      }
      // 1а. Агентский инструмент без признака: очередь 3 — обязательный отказ (A1 п. 8.3); 1–2 — агент и мандат по домену
      // токена на п. 2 (РП22 п. 6, РП48 (г)); ACCOUNT_LINK — до PS-21 не подтверждено.
      if (this.opts.params.aoi_rollout_phase === 3) return no("AOI_MISSING");
      if (kind !== "AGENT_TOKEN") return no("CREDENTIAL_INVALID");
    } else if (kind === "CARD_TOKEN" && aoi.indicator === false) {
      // Противоречивый признак: false с кодом агента или мандатом (без них — BYPASS выше). Сигнал ошибки эквайрера —
      // в ветку CARD_TOKEN с признаком на п. 2: CREDENTIAL_INVALID и счётчик РП48 (а) (РП49 (в) п. 3, «да» владельца 21.10).
    } else if (aoi.indicator !== true || !wellFormedCode(aoi.agent_code)) {
      return no("AOI_MISSING");
    }
    // Код агента признака проверен выше; без признака агент — из домена токена на п. 2.
    const aoiCode = aoi === undefined ? undefined : aoi.agent_code;

    // 2. Домен токена (РП47 п. 6): только AGENT_TOKEN, до реестра; домен — из записи токена Платформы, а не из aoi.
    // Без признака (очередь 1–2) агент и мандат — из домена: сверять не с чем (РП48 (г)). ACCOUNT_LINK — до PS-21 не
    // подтверждено (РП43 п. 7). Неизвестный вид с aoi — реквизит не опознан: CREDENTIAL_INVALID и инцидент (доп. РП43
    // п. 13). CARD_TOKEN с aoi — не реквизит П5 (нет домена и криптограммы): CREDENTIAL_INVALID и инцидент со счётчиком
    // по эквайреру и продавцу (РП48 (а)); без aoi он — BYPASS выше (инвариант 2).
    const credentials = this.opts.credentials;
    const token_ref = msg.instrument?.token_ref;
    let agent_code: string;
    let mandate_id: unknown;
    // Наборы MCC домена токена (РП49 (д)) — для п. 6; null — токен выпущен до sql/110.
    let tokenMcc: TokenRecord["merchant_mcc"] = null;
    if (kind === "AGENT_TOKEN") {
      if (!credentials || typeof token_ref !== "string" || token_ref === "") return no("CREDENTIAL_INVALID");
      let token: Pick<TokenRecord, "agent_code" | "mandate_id" | "merchant_mcc"> | undefined;
      try {
        token = await credentials.tokenByRef(token_ref);
      } catch {
        this.log("warn", { op_ref: msg.op_ref }, "ADP: запись токена не прочитана");
        return no("STATE_UNAVAILABLE");
      }
      if (!token) return no("CREDENTIAL_INVALID");
      if (aoi !== undefined && (token.agent_code !== aoiCode || token.mandate_id !== aoi.mandate_id)) {
        // Недостоверный код агента или мандат в признаке (A1 п. 8.2); в журнал — коды, без реквизитов инструмента.
        this.log("warn", { op_ref: msg.op_ref, agent_code: aoiCode, incident: true }, "ADP: признак не совпадает с доменом токена");
        return no("AOI_MISMATCH");
      }
      agent_code = token.agent_code;
      mandate_id = token.mandate_id;
      tokenMcc = token.merchant_mcc;
    } else {
      if (kind === "CARD_TOKEN") {
        // Ложный признак эквайрера отклоняет и покупку человека (остаточный риск РП48 (а)) — счётчик показывает источник.
        const acquirer_id = msg.merchant?.acquirer_id ?? null;
        const merchant_id = msg.merchant?.id ?? null;
        const pair = JSON.stringify([acquirer_id, merchant_id]);
        const count = (this.cardTokenAoi.get(pair) ?? 0) + 1;
        this.cardTokenAoi.set(pair, count);
        this.log(
          "warn",
          // Код агента — только по форме: у противоречивого признака (РП49 (в)) он не проверен на п. 1 (инвариант 1).
          { op_ref: msg.op_ref, acquirer_id, merchant_id, agent_code: wellFormedCode(aoiCode) ? aoiCode : null, count, incident: true },
          "ADP: CARD_TOKEN с признаком агента — не агентский реквизит",
        );
      } else if (!agentInstrument) {
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

    // 4. Криптограмма (РП47 п. 7): запись реквизита по токену и SHA-256 криптограммы; нет, истекла (часы Платформы), не
    // ISSUED, другой продавец — CREDENTIAL_INVALID. Сумма против amount_max — на п. 7 (там известен клиент для уведомления).
    let cred: CredentialRecord | undefined;
    if (kind === "AGENT_TOKEN" && credentials && typeof token_ref === "string") {
      const cryptogram = msg.instrument.cryptogram;
      if (typeof cryptogram !== "string" || cryptogram === "") return no("CREDENTIAL_INVALID");
      try {
        cred = await credentials.credentialByCryptogram(token_ref, sha256Hex(cryptogram));
      } catch {
        this.log("warn", { op_ref: msg.op_ref }, "ADP: запись реквизита не прочитана");
        return no("STATE_UNAVAILABLE");
      }
      if (!cred || cred.status !== "ISSUED" || !(Date.parse(cred.valid_to) > this.now().getTime())) return no("CREDENTIAL_INVALID");
      if (cred.merchant_id !== msg.merchant?.id) return no("CREDENTIAL_INVALID");
    }

    // 5. Мандат агента (чужой = неизвестный), статус — по свёртке журнала (инвариант 5).
    if (typeof mandate_id !== "string" || mandate_id === "") return no("MANDATE_NOT_FOUND");
    const m = await this.mandate(mandate_id, agent_code, msg.op_ref);
    if (m === "unavailable") return no("STATE_UNAVAILABLE", mandate_id);
    if (!m) return no("MANDATE_NOT_FOUND", mandate_id);
    // Мандат домена токена — только CART (РП49 (б)): токен выпускается только по CART (РП47 п. 2), другой тип — нарушение
    // целостности записей Платформы, а не ошибка агента. До статуса: отозванный INTENT не должен дать MANDATE_REVOKED.
    if (kind === "AGENT_TOKEN" && m.type !== "CART") {
      this.log("warn", { op_ref: msg.op_ref, agent_code, mandate_id, incident: true }, "ADP: мандат домена токена не CART");
      return no("STATE_UNAVAILABLE", mandate_id);
    }
    if (m.client) notify = { participant_code: m.client.participant_code, principal_ref: m.client.principal_ref, agent_code };
    const statusReason = this.statusReason(m);
    if (statusReason) return no(statusReason, mandate_id);

    // 6. Продавец и валюта — в области мандата; MCC — по домену токена (PS-14).
    const merchant = msg.merchant?.id;
    if (merchant === undefined || !m.merchant_scope.includes(merchant)) return no("MANDATE_SCOPE", mandate_id);
    if (msg.currency !== m.currency) return no("MANDATE_SCOPE", mandate_id);
    // MCC сообщения — в наборе продавца из домена токена (РП49 (д) п. 4), только AGENT_TOKEN. Набора нет (токен до sql/110,
    // п. 5), нет записи продавца области или она не по форме («Нюансы РП49» п. 7) — порча записей Платформы: не
    // подтверждено и инцидент.
    // Object.hasOwn — запись самого продавца, а не свойство прототипа.
    if (kind === "AGENT_TOKEN") {
      const set =
        tokenMcc !== null && typeof tokenMcc === "object" && !Array.isArray(tokenMcc) && Object.hasOwn(tokenMcc, merchant)
          ? tokenMcc[merchant]
          : undefined;
      // Запись не по форме (не массив, пуста, есть не строки) — тоже порча: при выпуске такой набор не записывается.
      if (!Array.isArray(set) || set.length === 0 || !set.every((x) => typeof x === "string")) {
        this.log("warn", { op_ref: msg.op_ref, agent_code, mandate_id, incident: true }, "ADP: в домене токена нет набора MCC продавца");
        return no("STATE_UNAVAILABLE", mandate_id);
      }
      const mcc = msg.merchant?.mcc;
      if (typeof mcc !== "string" || !set.includes(mcc)) return no("MANDATE_SCOPE", mandate_id);
    }

    // Тип мандата вне перечня (данные, а не тип) — не подтверждено, а не «как INTENT» (инвариант 3, как доп. РП43 п. 19).
    if (m.type !== "INTENT" && m.type !== "CART") return no("STATE_UNAVAILABLE", mandate_id);

    // Лимиты клиента мандата — одно чтение на решение (РП45 п. 1–2): MCC (п. 6), per_operation (п. 7), порог (п. 10),
    // per_period (п. 11). Записи нет — только предел мандата; не прочитана, не по форме, другая валюта — не подтверждено.
    const read = await this.clientLimits(msg, m, mandate_id);
    if (read === "unavailable") return no("STATE_UNAVAILABLE", mandate_id);
    const limits = read?.current;
    if (limits?.merchant_categories !== undefined) {
      const mcc = msg.merchant?.mcc;
      if (mcc === undefined || !limits.merchant_categories.includes(mcc)) return no("MANDATE_SCOPE", mandate_id);
    }
    if (limits?.per_operation !== undefined && msg.amount > limits.per_operation) return no("LIMIT_EXCEEDED", mandate_id, "CLIENT");
    // 7. Ограничение инструмента (A3 п. 7.2, РП47 п. 7): сумма > amount_max или валюта ≠ валюте реквизита. Источник предела
    // в уведомлении — INSTRUMENT (РП49 (е), ПИ-8).
    if (cred && (msg.amount > cred.amount_max || msg.currency !== cred.currency)) return no("LIMIT_EXCEEDED", mandate_id, "INSTRUMENT");
    const client = read?.period && m.client ? this.clientAccount(m.client, read.period) : undefined;

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
    const threshold = this.threshold(msg, mandate_id, limits && clientThreshold(limits));
    if (threshold === undefined) return no("STATE_UNAVAILABLE", mandate_id);
    if (msg.amount > threshold) return this.confirm(accounts, client, msg.amount, mandate_id, false, no);

    // 9. Дробление (РП44 п. 1–4): операция не выше порога — доля, если в окне по корневому INTENT (у CART — родитель)
    // вместе с ней ≥ split_min_ops одобрений и сумма выше порога. Доля в окно не входит; вход — до резерва, отказ резерва
    // убирает запись из окна решением DECLINE. Окно не прочитано — не подтверждено, не «окна нет».
    const window_key = accounts.at(-1)?.id ?? mandate_id;
    const at_ms = this.now().getTime();
    let w: WindowResult;
    try {
      w = await this.opts.operations.enterWindow(
        msg.op_ref,
        { key: window_key, amount: msg.amount, currency: msg.currency, at_ms },
        { since_ms: at_ms - this.opts.params.split_window_sec * 1000, threshold, min_ops: this.opts.params.split_min_ops },
      );
    } catch {
      this.log("warn", { op_ref: msg.op_ref, mandate_id }, "ADP: окно дробления не прочитано");
      return no("STATE_UNAVAILABLE", mandate_id);
    }
    if (!w.entered) {
      // Телеметрия ПС12: сигнал, не инцидент; реквизитов инструмента нет (инвариант 1, РП44 п. 7).
      const fields = { op_ref: msg.op_ref, mandate_id, window_key, ops: w.ops, sum: w.sum, currency: msg.currency, split_detected: true };
      this.log("warn", fields, "ADP: дробление по мандату в окне");
      return this.confirm(accounts, client, msg.amount, mandate_id, true, no);
    }

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
        return no(reason, mandate_id, "MANDATE");
      }
      holds.push(r.hold.id);
    }
    // Лимит клиента за период — второй счёт ядра тем же op_key после счетов мандата (РП45 п. 1); отказ — освобождение
    // резервов мандата и причина счёта клиента.
    if (client) {
      const r = await this.opts.state.reserveClient(client, money, msg.op_ref);
      if (!r.ok) {
        for (const h of holds) await this.release(h, msg.op_ref);
        const reason = STATE_TO_PI[r.code];
        if (reason === "INVALID") throw new AdpRequestInvalid("amount");
        if (r.code === "IDEMPOTENCY_CONFLICT" || r.code === "RESERVATION_RELEASED") {
          this.log("warn", { op_ref: msg.op_ref, mandate_id, incident: true }, "ADP: резерв лимита клиента по op_ref — повтор не того вида");
        }
        return no(reason, mandate_id, "CLIENT");
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
    // Погашение криптограммы (РП47 п. 8): только у APPROVE, после резерва и сверки статуса, условной записью ISSUED → USED.
    // Погасила другая авторизация (в том числе на другом экземпляре) — освобождение и CREDENTIAL_INVALID (A3 п. 4.4);
    // сбой записи — освобождение и не подтверждено. AGENT_TOKEN без записи реквизита сюда дойти не должен (п. 2 и 4);
    // дошёл — не APPROVE без погашения, а освобождение и не подтверждено (ревью КТ1 З4, инвариант 3).
    if (kind === "AGENT_TOKEN" && (!cred || !credentials)) {
      for (const h of holds) await this.release(h, msg.op_ref);
      this.log("warn", { op_ref: msg.op_ref, mandate_id, incident: true }, "ADP: агентский токен без записи реквизита к погашению");
      return no("STATE_UNAVAILABLE", mandate_id);
    }
    if (cred && credentials) {
      let consumed: boolean;
      try {
        consumed = await credentials.consume(cred.credential_ref, msg.op_ref);
      } catch {
        this.log("warn", { op_ref: msg.op_ref, mandate_id }, "ADP: погашение реквизита не записано");
        for (const h of holds) await this.release(h, msg.op_ref);
        return no("STATE_UNAVAILABLE", mandate_id);
      }
      if (!consumed) {
        for (const h of holds) await this.release(h, msg.op_ref);
        this.log("warn", { op_ref: msg.op_ref, mandate_id }, "ADP: криптограмма уже погашена другой авторизацией");
        return no("CREDENTIAL_INVALID", mandate_id);
      }
    }
    const left = await this.leftOf(accounts, client);
    // Счёт клиента и остаток после резерва — для client.limit_exhausted (РП46 (б) п. 2); остаток уже прочитан для ответа.
    const clientFacts =
      client && left?.client !== undefined ? { client_account: clientAccountId(client), client_left_after: left.client } : {};
    return {
      reason: null,
      mandate_id,
      holds,
      agent_level: agent.level,
      ...(left === undefined ? {} : { left: minLeft(left) }),
      ...(notify ? { notify: { ...notify, ...clientFacts } } : {}),
    };
  }

  /**
   * Подтверждение вместо резерва (доп. РП43 п. 15, РП44 п. 1): остаток — чтением без резерва (проверки 7–8 идут раньше);
   * меньше суммы — LIMIT_EXCEEDED, не прочитан — STATE_UNAVAILABLE.
   */
  private async confirm(
    accounts: readonly { readonly id: string; readonly limit: number }[],
    client: ClientAccount | undefined,
    amount: number,
    mandate_id: string,
    split: boolean,
    no: (reason: DecisionReason, mandate_id: string, source?: LimitSource) => Declined,
  ): Promise<Verdict> {
    const left = await this.leftOf(accounts, client);
    if (left === undefined) return no("STATE_UNAVAILABLE", mandate_id);
    // Чей предел: мандата, если его остатка не хватает, иначе — лимита клиента (РП46 доп. п. 7).
    if (minLeft(left) < amount) return no("LIMIT_EXCEEDED", mandate_id, left.mandate < amount ? "MANDATE" : "CLIENT");
    return { ...no("CONFIRMATION_REQUIRED", mandate_id), split };
  }

  /**
   * Лимиты клиента мандата (РП45 п. 1): действующая запись и лимит за период по истории версий (расширение — со
   * следующего периода). Записей нет — undefined (только предел мандата); мандат без клиента, сбой, версия не по форме,
   * валюта действующей записи или лимита за период ≠ валюте операции — unavailable.
   */
  private async clientLimits(
    msg: CanonicalMessage,
    m: AdpMandate,
    mandate_id: string,
  ): Promise<{ readonly current: ClientLimits; readonly period: PeriodLimit | undefined } | undefined | "unavailable"> {
    const fields = { op_ref: msg.op_ref, mandate_id };
    if (!m.client) {
      this.log("warn", fields, "ADP: клиент мандата не определён — нет подписи банка у корня");
      return "unavailable";
    }
    let raw: unknown;
    try {
      raw = await this.opts.clientLimits.get(m.client);
    } catch {
      this.log("warn", fields, "ADP: лимиты клиента не прочитаны");
      return "unavailable";
    }
    if (!Array.isArray(raw)) {
      this.log("warn", fields, "ADP: лимиты клиента не по форме");
      return "unavailable";
    }
    const versions: { limits: ClientLimits; received_at: string }[] = [];
    for (const v of raw as unknown[]) {
      const o = (typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>;
      const p = parseLimits(o.limits);
      if (!p.ok || typeof o.received_at !== "string" || Number.isNaN(Date.parse(o.received_at))) {
        this.log("warn", fields, "ADP: запись лимитов клиента не по форме");
        return "unavailable";
      }
      versions.push({ limits: p.limits, received_at: o.received_at });
    }
    const current = versions.at(-1)?.limits;
    if (!current) return undefined;
    let period: PeriodLimit | undefined;
    try {
      period = effectivePeriodLimit(versions, this.opts.params.client_limit_period_tz, this.now());
    } catch {
      this.log("warn", fields, "ADP: лимит клиента за период не вычислен");
      return "unavailable";
    }
    if ((current.currency !== undefined && current.currency !== msg.currency) || (period && period.currency !== msg.currency)) {
      this.log("warn", { ...fields, currency: msg.currency }, "ADP: валюта лимитов клиента ≠ валюте операции");
      return "unavailable";
    }
    return { current, period };
  }

  /** Счёт лимита клиента за период (РП45 п. 1). Период — часы Платформы. */
  private clientAccount(c: ClientRef, l: PeriodLimit): ClientAccount {
    return {
      ...c,
      period: l.period,
      period_start: periodStart(l.period, this.opts.params.client_limit_period_tz, this.now()),
      limit: { amount: l.per_period, currency: l.currency },
    };
  }

  /** Действующий порог в единицах валюты операции; клиентский не по форме или другая валюта — undefined. */
  private threshold(msg: CanonicalMessage, mandate_id: string, raw: unknown): number | undefined {
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

  /**
   * Остаток для ответа: меньшее по счетам (у CART — CART и родитель, РП43 п. 6) и лимиту клиента за период (РП45 п. 1);
   * не прочитан хоть один — undefined.
   */
  private async leftOf(
    accounts: readonly { readonly id: string; readonly limit: number }[],
    client?: ClientAccount,
  ): Promise<Left | undefined> {
    let min: number | undefined;
    for (const a of accounts) {
      const left = await this.opts.state.amountLeft(a.id, a.limit);
      if (left === undefined) return undefined;
      min = min === undefined ? left : Math.min(min, left);
    }
    if (min === undefined) return undefined;
    if (!client) return { mandate: min };
    const left = await this.opts.state.clientLeft(client);
    return left === undefined ? undefined : { mandate: min, client: left };
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
