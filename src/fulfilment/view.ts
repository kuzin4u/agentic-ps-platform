// П8 Операция агенту — GET /pao/v1/operations/{op_ref} (РП52 п. 10, РП53 п. 10): итог — из записи итога, а без неё — из
// решения в записи операции ADP (DECLINE, CONFIRMATION_REQUIRED), независимо от сборщика и его горизонта («Дополнения»
// РП52 п. 1). Агент — по домену токена в записи Платформы (инвариант 5). Только ссылки и коды: token_ref нет (инвариант 1).
import type { OperationReader, OperationRecord } from "../adp/operations.js";
import type { Aoi as CanonicalAoi } from "../shared/canonical.generated.js";
import type { Aoi, Operation } from "../shared/pao.js";
import type { OperationOutcome, OutcomeStatus, OutcomeStore } from "./outcomes.js";
import type { FulfilmentRecord, FulfilmentStore } from "./records.js";
import type { ReversalStore } from "./reversals.js";

/** Объект fulfilment ПАО 1.4.0 (РП53 п. 8): currency и прочие поля записи агенту — с 1.5.0 (#37). */
const fulfilmentView = (f: FulfilmentRecord): NonNullable<Operation["fulfilment"]> => ({
  fulfilment_ref: f.fulfilment_ref,
  final_amount: f.final_amount,
  scope_check: f.scope_check,
  spent_position: f.spent_position,
  at: f.at,
});

export interface OperationViewDeps {
  readonly operations: OperationReader;
  readonly outcomes: Pick<OutcomeStore, "get">;
  /** Записи об исполнении (РП53 п. 10): есть — SETTLED с fulfilment; без хранилища — как до ч. 2. */
  readonly fulfilments?: Pick<FulfilmentStore, "get">;
  /** Реверсалы (РП55 п. 1): есть — REVERSED с reason REVERSAL / AUTH_EXPIRED; без хранилища — как до ч. 3. */
  readonly reversals?: Pick<ReversalStore, "get">;
}

/** Агент операции: из итога, а без него — как у сборщика (факты, затем столбец уведомителя у записей до sql/114). */
const agentOf = (rec: OperationRecord, outcome: OperationOutcome | undefined): string | null =>
  outcome ? outcome.agent_code : (rec.facts?.agent_code ?? rec.notify?.agent_code ?? null);

/** Итог по решению ADP без записи итога: APPROVE ждёт эмитента, запись «в работе» — итога нет. */
function fromDecision(rec: OperationRecord): { status: OutcomeStatus; reason: string | null } | undefined {
  const d = rec.decision;
  if (d?.decision === "DECLINE") return { status: "DECLINED", reason: d.reason ?? null };
  if (d?.decision === "CONFIRMATION_REQUIRED") return { status: "CONFIRMATION_REQUIRED", reason: null };
  return undefined;
}

/** Признак как пришёл (A1 п. 5.1), если в нём все обязательные поля Aoi ПАО; неполный — опускается, не дополняется. */
function paoAoi(a: CanonicalAoi | null | undefined): { aoi?: Aoi } {
  if (!a || typeof a.indicator !== "boolean" || typeof a.agent_code !== "string" || typeof a.mandate_id !== "string") return {};
  return { aoi: { ...a, indicator: a.indicator, agent_code: a.agent_code, mandate_id: a.mandate_id } };
}

/**
 * Операция этого агента или undefined — чужая, неизвестная, без установленного агента, без итога (400 одним ответом,
 * РП51 п. 8). Поля фактов, которых в записи нет (записи до sql/114, факт не по форме), опускаются — не догадка.
 * Сбой чтения — исключение (→ 503).
 */
export async function operationFor(deps: OperationViewDeps, agent_code: string, op_ref: string): Promise<Operation | undefined> {
  const rec = await deps.operations.get(op_ref);
  if (!rec) return undefined;
  const outcome = await deps.outcomes.get(op_ref);
  if (agentOf(rec, outcome) !== agent_code) return undefined;
  const decided = outcome ? { status: outcome.status, reason: outcome.status === "DECLINED" ? outcome.reason : null } : fromDecision(rec);
  // Реверсал — по APPROVE ADP с итогом AUTHORIZED или до ответа эмитента (РП55 п. 1); после клиринга не записывается.
  const reversal = rec.decision?.decision === "APPROVE" && (!outcome || outcome.status === "AUTHORIZED") ? await deps.reversals?.get(op_ref) : undefined;
  const result: { status: Operation["status"]; reason: string | null } | undefined = reversal ? { status: "REVERSED", reason: reversal.kind } : decided;
  if (!result) return undefined;
  // Клиринг — только после AUTHORIZED (РП53 п. 3): запись об исполнении меняет статус на SETTLED.
  const settled = result.status === "AUTHORIZED" ? await deps.fulfilments?.get(op_ref) : undefined;
  const f = rec.facts;
  return {
    op_ref,
    ...(f?.order_ref != null ? { order_ref: f.order_ref } : {}),
    ...(f?.channel != null ? { channel: f.channel } : {}),
    ...(f ? { amount: f.amount } : {}),
    ...(f?.merchant_id != null ? { merchant_id: f.merchant_id } : {}),
    // AOI_MISMATCH: признак называет другого агента и чужой мандат — агенту не отдаётся (решение владельца на КТ1 № 10);
    // полный признак остаётся в записи Платформы для спора (PS-22).
    ...(result.reason === "AOI_MISMATCH" ? {} : paoAoi(f?.aoi)),
    status: settled ? "SETTLED" : result.status,
    reason: settled ? null : result.reason,
    fulfilment: settled ? fulfilmentView(settled) : null,
    deal_ref: null,
  };
}
