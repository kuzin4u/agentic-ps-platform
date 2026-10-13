// Эмулятор эквайрера (ПИ-2, РП22 п. 6, п. 8): авторизацию строит эквайрер из пакета, полученного от продавца,
// у агента пути к эквайреру нет (РП2). Сумма — из заказа продавца, не из пакета агента (инвариант 5).
// Два режима: с переносом aoi без изменений (A1 п. 4.3) и без поддержки aoi — тогда операция остаётся
// агентской по инструменту AGENT_TOKEN / ACCOUNT_LINK, ADP определяет агента по домену токена (ФП4).
import type { CanonicalMessage, Instrument, Merchant } from "../../shared/canonical.generated.js";
import type { AcquirerMessage, OpkcAuthResult, OpkcPort } from "./opkc-port.js";
import type { PaymentPackage } from "./package.js";

export interface AcquirerOptions {
  readonly acquirer_id: string;
  /** false — эквайрер не переносит aoi в сообщения процессинга (РП22 п. 6). */
  readonly aoiSupport: boolean;
  readonly opkc: OpkcPort;
  readonly now?: () => Date;
}

/** Авторизация от продавца: агентская — с пакетом, неагентская — с обычным токеном карты. */
export type AuthorizeInput = {
  readonly merchant: Omit<Merchant, "acquirer_id">;
  readonly amount: number;
  readonly currency: string;
  readonly order_ref: string;
} & (
  | { readonly package: PaymentPackage; readonly instrument?: undefined }
  | { readonly package?: undefined; readonly instrument: Instrument & { readonly kind: "CARD_TOKEN" } }
);

export class Acquirer {
  readonly acquirer_id: string;
  readonly aoiSupport: boolean;
  private readonly now: () => Date;
  readonly #sent = new Map<string, CanonicalMessage>();

  constructor(private readonly opts: AcquirerOptions) {
    this.acquirer_id = opts.acquirer_id;
    this.aoiSupport = opts.aoiSupport;
    this.now = opts.now ?? (() => new Date());
  }

  async authorize(input: AuthorizeInput): Promise<OpkcAuthResult> {
    if (!Number.isSafeInteger(input.amount) || input.amount <= 0) throw new Error("Сумма — целое число копеек > 0");
    const pkg = input.package;
    let instrument: Instrument;
    if (pkg) instrument = instrumentOf(pkg);
    else if (input.instrument?.kind === "CARD_TOKEN") instrument = { ...input.instrument };
    else throw new Error("Неагентская авторизация — только с CARD_TOKEN");
    const msg: AcquirerMessage = {
      msg_type: "AUTH_REQUEST",
      channel: instrument.kind === "ACCOUNT_LINK" ? "SBP" : "CARD",
      amount: input.amount,
      currency: input.currency,
      merchant: { ...input.merchant, acquirer_id: this.acquirer_id },
      instrument,
      // Признак переносится как сформирован (A1 п. 4.3); без поддержки — не переносится вовсе.
      ...(pkg && this.aoiSupport ? { aoi: structuredClone(pkg.aoi) } : {}),
      order_ref: input.order_ref,
      ts: this.now().toISOString(),
    };
    const r = await this.opts.opkc.authorize(msg);
    this.#sent.set(r.op_ref, { op_ref: r.op_ref, ...structuredClone(msg) });
    return r;
  }

  /** Реверсал авторизации: те же инструмент, сумма и признак (A1 п. 5.1). */
  async reverse(op_ref: string): Promise<void> {
    const auth = this.#sent.get(op_ref);
    if (!auth) throw new Error(`Нет авторизации ${op_ref}`);
    await this.opts.opkc.reverse({ ...structuredClone(auth), msg_type: "REVERSAL", ts: this.now().toISOString() });
  }
}

/** Инструмент из пакета: только ссылки на токен или привязку, номера карты нет (инвариант 1). */
function instrumentOf(pkg: PaymentPackage): Instrument {
  if (pkg.kind === "CARD" && pkg.payload.token_ref && pkg.payload.cryptogram) {
    return { kind: "AGENT_TOKEN", token_ref: pkg.payload.token_ref, cryptogram: pkg.payload.cryptogram };
  }
  if (pkg.kind === "SBP" && pkg.payload.account_link_ref) {
    return { kind: "ACCOUNT_LINK", account_link_ref: pkg.payload.account_link_ref };
  }
  throw new Error(`Пакет без инструмента вида ${pkg.kind}`);
}
