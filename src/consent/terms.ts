// П2 Реквизиты мандата до записи в журнал (PS-06 К1.2; A7 п. 1–2, 5; инварианты 1, 3, 5).
// Журнал неизменяем — ошибку в записи не исправить, поэтому проверка здесь, а не только в шлюзе (К1.3):
// в запись идут только поля утверждённого перечня (PR #30), прочие поля тела отбрасываются.
import type { MandateRequest } from "../shared/pao.js";
import { parseRfc3339, type MandateSubject, type MandateTerms } from "./model.js";

/** Основания отказа в записи мандата; шлюз сопоставляет их с кодами ПАО в К1.3. */
export type ConsentRejectReason =
  | "FIELD_INVALID"
  | "PARENT_NOT_FOUND"
  | "PARENT_NOT_ACTIVE"
  | "PARENT_MISMATCH"
  | "SCOPE_WIDENED";

export class ConsentRequestRejected extends Error {
  constructor(
    readonly reason: ConsentRejectReason,
    readonly field: string,
    /** Статус родителя при PARENT_NOT_ACTIVE: по нему шлюз выбирает код ПАО (РП33 п. 1). */
    readonly parentStatus?: string,
  ) {
    super(`CONSENT_REQUEST_REJECTED: ${reason}: ${field}${parentStatus ? `: ${parentStatus}` : ""}`);
  }
}

const reject = (reason: ConsentRejectReason, field: string): never => {
  throw new ConsentRequestRejected(reason, field);
};

/**
 * principal_ref — непрозрачный идентификатор клиента (инвариант 1; решение владельца, PR #30): буквы латиницы, цифры,
 * `_` и `-`, до 64 знаков, без семи и более цифр подряд — так не проходят номер карты и телефон; `@`, `+`, пробел
 * (адрес, телефон, ФИО) не проходят набором знаков.
 */
export const isOpaquePrincipalRef = (v: unknown): v is string =>
  typeof v === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(v) && !/\d{7,}/.test(v);

const isPositiveInt = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 1;
const isNonNegInt = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const isText = (v: unknown, max = 1024): v is string => typeof v === "string" && v.length >= 1 && v.length <= max;
const oneOf = <T extends string>(v: unknown, xs: readonly T[]): v is T => typeof v === "string" && (xs as readonly string[]).includes(v);

/** Открытые реквизиты — явным перечнем; поля тела сверх перечня (signature_type, status, pan…) не попадают в запись. */
/** now = null — без проверки срока: сверка повтора с записанным мандатом в любой срок (РП33 доп.). */
export function pickTerms(agent_code: string, req: MandateRequest, now: Date | null): MandateTerms {
  const r = req as Partial<Record<keyof MandateRequest, unknown>>;
  if (!oneOf(r.type, ["INTENT", "CART"] as const)) reject("FIELD_INVALID", "type");
  const parent_id = (r.parent_id ?? null) as string | null;
  if (parent_id !== null && !isText(parent_id, 64)) reject("FIELD_INVALID", "parent_id");
  // INTENT — корневой; CART — самостоятельный или под INTENT (A7 п. 1.1–1.2).
  if (r.type === "INTENT" && parent_id !== null) reject("FIELD_INVALID", "parent_id");
  if (!isPositiveInt(r.amount_limit)) reject("FIELD_INVALID", "amount_limit");
  if (typeof r.currency !== "string" || !/^[A-Z]{3}$/.test(r.currency)) reject("FIELD_INVALID", "currency");
  const validTo = parseRfc3339(r.valid_to);
  if (Number.isNaN(validTo) || (now !== null && validTo <= now.getTime())) reject("FIELD_INVALID", "valid_to");
  if (!Array.isArray(r.merchant_scope) || !r.merchant_scope.every((m) => isText(m, 64))) {
    reject("FIELD_INVALID", "merchant_scope");
  }
  if (!isOpaquePrincipalRef(r.principal_ref)) reject("FIELD_INVALID", "principal_ref");
  if (!oneOf(r.mode, ["IMMEDIATE", "AUTONOMOUS"] as const)) reject("FIELD_INVALID", "mode");
  if (r.period !== undefined && !isText(r.period, 64)) reject("FIELD_INVALID", "period");
  if (r.key_terms_shown !== undefined && typeof r.key_terms_shown !== "boolean") reject("FIELD_INVALID", "key_terms_shown");
  const settlement = r.settlement_mode ?? "DIRECT";
  if (!oneOf(settlement, ["DIRECT", "CONDITIONAL"] as const)) reject("FIELD_INVALID", "settlement_mode");
  const c = r.conditional ?? null;
  // conditional — только при settlement_mode=CONDITIONAL (ПАО), и тогда обязателен.
  if ((settlement === "CONDITIONAL") !== (c !== null)) reject("FIELD_INVALID", "conditional");
  let conditional: MandateTerms["conditional"] = null;
  if (c !== null) {
    const cc = c as Record<string, unknown>;
    if (typeof c !== "object" || !isText(cc.provider, 64) || !isText(cc.deal_ref, 128)) reject("FIELD_INVALID", "conditional");
    conditional = { provider: cc.provider as string, deal_ref: cc.deal_ref as string };
  }
  return {
    type: r.type as MandateTerms["type"],
    parent_id,
    agent_code,
    amount_limit: r.amount_limit as number,
    currency: r.currency as string,
    ...(r.period !== undefined ? { period: r.period as string } : {}),
    valid_to: r.valid_to as string,
    merchant_scope: [...(r.merchant_scope as string[])],
    principal_ref: r.principal_ref as string,
    mode: r.mode as MandateTerms["mode"],
    settlement_mode: settlement as MandateTerms["settlement_mode"],
    conditional,
    ...(r.key_terms_shown !== undefined ? { key_terms_shown: r.key_terms_shown as boolean } : {}),
  };
}

/** Предмет — явным перечнем: у CART корзина обязательна, у INTENT её нет; итог корзины — в пределах суммы. */
export function pickSubject(req: MandateRequest, amount_limit: number): MandateSubject {
  if (!isText(req.subject, 2048)) reject("FIELD_INVALID", "subject");
  const raw = req.cart ?? null;
  if (req.type === "INTENT") {
    if (raw !== null) reject("FIELD_INVALID", "cart");
    return { subject: req.subject, cart: null };
  }
  if (raw === null || typeof raw !== "object") return reject("FIELD_INVALID", "cart");
  const items = raw.items;
  if (!isText(raw.merchant_id, 64) || !Array.isArray(items) || items.length === 0) reject("FIELD_INVALID", "cart");
  const picked = (items ?? []).map((i) => {
    if (typeof i !== "object" || i === null || !isText(i.sku, 128) || !isPositiveInt(i.qty) || !isNonNegInt(i.price)) {
      return reject("FIELD_INVALID", "cart.items");
    }
    return { sku: i.sku, qty: i.qty, price: i.price };
  });
  if (!isNonNegInt(raw.total) || raw.total > amount_limit) reject("FIELD_INVALID", "cart.total");
  return { subject: req.subject, cart: { merchant_id: raw.merchant_id as string, items: picked, total: raw.total as number } };
}

/**
 * CART под INTENT — только сужение (A7 п. 5.1–5.2): тот же принципал и валюта, сумма и срок не больше, область
 * продавцов — подмножество, продавец корзины — в области родителя. Расширение — новым мандатом с подтверждением.
 */
export function assertNarrows(child: MandateTerms, subj: MandateSubject, parent: MandateTerms): void {
  if (parent.type !== "INTENT") reject("PARENT_MISMATCH", "parent_id");
  if (child.principal_ref !== parent.principal_ref) reject("PARENT_MISMATCH", "principal_ref");
  if (child.currency !== parent.currency) reject("PARENT_MISMATCH", "currency");
  if (child.amount_limit > parent.amount_limit) reject("SCOPE_WIDENED", "amount_limit");
  if (parseRfc3339(child.valid_to) > parseRfc3339(parent.valid_to)) reject("SCOPE_WIDENED", "valid_to");
  const scope = new Set(parent.merchant_scope);
  if (!child.merchant_scope.every((m) => scope.has(m))) reject("SCOPE_WIDENED", "merchant_scope");
  if (!subj.cart?.merchant_id || !scope.has(subj.cart.merchant_id)) reject("SCOPE_WIDENED", "cart.merchant_id");
}
