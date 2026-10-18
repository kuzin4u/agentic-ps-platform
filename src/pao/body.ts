// П9 Проверка тела изменяющих методов по схеме метода (РП31 п. 1): до обработчика и до захвата ключа идемпотентности.
// Схема — вручную; совпадение обязательных полей с agent-protocol.yaml сверяет tests/contract/pao-bodies.test.ts.
// Лишние поля игнорируются (ПАО §7): класс и уровень в теле не читаются, они — только из реестра (инвариант 5).
import { parseRfc3339 } from "../consent/model.js";
import type { MandateRequest } from "../shared/pao.js";

/** Обязательные поля тела `POST /pao/v1/agent/keys` — строки (ПАО 1.3.0). */
export const KEY_REGISTRATION_REQUIRED = ["alg", "public_key"] as const;

export interface KeyRegistration {
  readonly alg: string;
  readonly public_key: string;
}

/** Тело `POST /pao/v1/agent/keys` или undefined — тогда REQUEST_INVALID. Возвращаются только поля схемы. */
export function keyRegistrationBody(raw: string): KeyRegistration | undefined {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  const alg = Object.hasOwn(o, "alg") ? o.alg : undefined;
  const public_key = Object.hasOwn(o, "public_key") ? o.public_key : undefined;
  if (typeof alg !== "string" || typeof public_key !== "string") return undefined;
  return { alg, public_key };
}

/** Обязательные поля `MandateRequest` (ПАО 1.3.0); сверка с YAML — tests/contract/pao-bodies.test.ts. */
export const MANDATE_REQUEST_REQUIRED = [
  "type",
  "subject",
  "amount_limit",
  "currency",
  "valid_to",
  "merchant_scope",
  "principal_ref",
  "mode",
] as const;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const optStr = (v: unknown) => v === undefined || typeof v === "string";
const optInt = (v: unknown) => v === undefined || Number.isSafeInteger(v);

/**
 * Тело `POST /pao/v1/mandates` по схеме `MandateRequest` (типы, перечни, `amount_limit` ≥ 1, `valid_to` — RFC 3339) или undefined —
 * тогда REQUEST_INVALID. Возвращаются только поля схемы; смысл реквизитов (формы, сроки, сужение) — журнал (terms.ts).
 */
export function mandateRequestBody(raw: string): MandateRequest | undefined {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!isObj(v)) return undefined;
  const g = (k: string) => own(v, k);
  const type = g("type");
  const mode = g("mode");
  const settlement = g("settlement_mode");
  const scope = g("merchant_scope");
  const amount = g("amount_limit");
  if (type !== "INTENT" && type !== "CART") return undefined;
  if (mode !== "IMMEDIATE" && mode !== "AUTONOMOUS") return undefined;
  if (settlement !== undefined && settlement !== "DIRECT" && settlement !== "CONDITIONAL") return undefined;
  for (const k of MANDATE_REQUEST_REQUIRED) if (!Object.hasOwn(v, k)) return undefined;
  for (const k of ["subject", "currency", "valid_to", "principal_ref"]) if (typeof g(k) !== "string") return undefined;
  if (!Number.isSafeInteger(amount) || (amount as number) < 1) return undefined;
  // format: date-time — часть схемы: неверный формат — до захвата ключа (РП31 п. 1); срок «не в прошлом» — журнал.
  if (Number.isNaN(parseRfc3339(g("valid_to")))) return undefined;
  if (!Array.isArray(scope) || !scope.every((m) => typeof m === "string")) return undefined;
  const parent = g("parent_id");
  if (parent !== undefined && parent !== null && typeof parent !== "string") return undefined;
  if (!optStr(g("period"))) return undefined;
  const shown = g("key_terms_shown");
  if (shown !== undefined && typeof shown !== "boolean") return undefined;

  let cart: MandateRequest["cart"];
  const c = g("cart");
  if (c === undefined || c === null) cart = c as null | undefined;
  else {
    if (!isObj(c) || !optStr(own(c, "merchant_id")) || !optInt(own(c, "total"))) return undefined;
    const items = own(c, "items");
    if (items !== undefined && !Array.isArray(items)) return undefined;
    const picked = [];
    for (const i of (items as unknown[] | undefined) ?? []) {
      if (!isObj(i) || !optStr(own(i, "sku")) || !optInt(own(i, "qty")) || !optInt(own(i, "price"))) return undefined;
      picked.push({ sku: own(i, "sku"), qty: own(i, "qty"), price: own(i, "price") } as { sku?: string; qty?: number; price?: number });
    }
    cart = {
      ...(own(c, "merchant_id") !== undefined ? { merchant_id: own(c, "merchant_id") as string } : {}),
      ...(items !== undefined ? { items: picked } : {}),
      ...(own(c, "total") !== undefined ? { total: own(c, "total") as number } : {}),
    };
  }
  let conditional: MandateRequest["conditional"];
  const cd = g("conditional");
  if (cd === undefined || cd === null) conditional = cd as null | undefined;
  else {
    if (!isObj(cd) || !optStr(own(cd, "provider")) || !optStr(own(cd, "deal_ref"))) return undefined;
    conditional = {
      ...(own(cd, "provider") !== undefined ? { provider: own(cd, "provider") as string } : {}),
      ...(own(cd, "deal_ref") !== undefined ? { deal_ref: own(cd, "deal_ref") as string } : {}),
    };
  }
  return {
    type,
    ...(parent !== undefined ? { parent_id: parent as string | null } : {}),
    subject: g("subject") as string,
    amount_limit: amount as number,
    currency: g("currency") as string,
    ...(g("period") !== undefined ? { period: g("period") as string } : {}),
    valid_to: g("valid_to") as string,
    merchant_scope: [...(scope as string[])],
    principal_ref: g("principal_ref") as string,
    mode,
    ...(shown !== undefined ? { key_terms_shown: shown } : {}),
    ...(cart !== undefined ? { cart } : {}),
    ...(settlement !== undefined ? { settlement_mode: settlement } : {}),
    ...(conditional !== undefined ? { conditional } : {}),
  };
}
