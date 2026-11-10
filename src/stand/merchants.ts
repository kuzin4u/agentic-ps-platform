// Эмуляторы продавцов и эквайрера для тестов агента (РП22 п. 8, AG-09): витрины проверяют подпись агента
// по каталогу ключей реестра стенда (та же функция, что отдаёт GET /.well-known/agent-keys). ОПКЦ — заглушка до PS-11.
// Срок кэша и окно перечитывания — merchant_jwks_max_age_sec и merchant_jwks_refetch_min_sec (РП56 п. 3; на стенде
// 1 и 1 с): отзыв ключа виден витрине не позже чем через секунду; явные значения — для тестов окна.
import type { FastifyInstance } from "fastify";
import { Acquirer, OpkcStub } from "../env/acquirer/index.js";
import {
  MerchantAgentVerifier,
  buildMerchantsServer,
  PAYMENT_REPLY_FAILURES,
  type OrderReplyFailure,
  type PackageMetadata,
  type PaymentReplyFailure,
  type ReconciliationPort,
  type Shop,
  type ShopListFailure,
} from "../env/merchants/index.js";
import type { MerchantFaultPort } from "../env/merchants/server.js";
import type { UiSettings } from "../ui/shared/index.js";
import { demoFaultsOf } from "./demo.js";
import type { Stand } from "./index.js";
import { registerShowcase, showcaseSettings } from "./showcase.js";

export interface MerchantsStandOptions {
  /** false — эквайрер без поддержки aoi (РП22 п. 6). По умолчанию true. */
  readonly aoiSupport?: boolean;
  readonly jwksMaxAgeMs?: number;
  readonly jwksRefetchMinMs?: number;
  /** Лимит обращений с адреса в минуту; по умолчанию — `merchant_rate_limit_per_min` стенда. */
  readonly rateLimitPerMin?: number;
  /**
   * Решение заглушки ОПКЦ; по умолчанию одобрение. Может быть асинхронным (РП72 п. 10): тест передаёт сообщение в ADP
   * стенда (`POST /adp/v1/decide`) — путь «витрина → ADP → подтверждение → витрина» без подмены до PS-11.
   */
  readonly decide?: ConstructorParameters<typeof OpkcStub>[0];
  /**
   * Замена `payment_methods` у витрин стенда (`stand.shops`) по `merchant_id` (#86, #106): значения — как есть, `[]`
   * допустим; неизвестный для набора стенда `merchant_id` — исключение. Знак, справочник продавцов и эквайрер стенда не
   * меняются; способ при оплате эмулятор не сверяет, зона витрины — по знаку. Своего набора витрин у `createMerchants`
   * нет — только `createStand({ shops })` (РП25 дополнение #106 п. 3).
   */
  readonly paymentMethods?: Readonly<Record<string, readonly string[]>>;
  /**
   * Страница витрин для человека (РП58 дополнение З12 п. 8): язык по умолчанию и бренд; по умолчанию —
   * `SHOWCASE_DEFAULT_SETTINGS`. Неверная настройка — исключение при создании.
   */
  readonly showcaseUi?: UiSettings;
}

/** Витрины стенда с заменой `payment_methods` (#86); `stand.shops` не меняется. */
function shopsWithMethods(base: readonly Shop[], methods: Readonly<Record<string, readonly string[]>>): readonly Shop[] {
  const known = new Set(base.map((s) => s.merchant_id));
  for (const id of Object.keys(methods)) {
    if (!known.has(id)) throw new Error(`paymentMethods: неизвестный merchant_id ${id}`);
  }
  return base.map((s) => (Object.hasOwn(methods, s.merchant_id) ? { ...s, payment_methods: [...methods[s.merchant_id]!] } : s));
}

export interface MerchantsStand {
  readonly app: FastifyInstance;
  readonly acquirer: Acquirer;
  /** Сообщения, ушедшие в ОПКЦ, — в канонической модели. */
  readonly opkc: OpkcStub;
  /** Метаданные пакетов, переданные для сверки при эквайрере без aoi. */
  readonly reconciliation: readonly PackageMetadata[];
  /** Ответы Платформы на метаданные эквайрера стенда (ПИ-8, РП57 п. 5): сверка или `{code}` — по порядку оплат. */
  readonly reconciliationReplies: readonly { readonly statusCode: number; readonly body: unknown }[];
  readonly verifier: MerchantAgentVerifier;
  /** Отказ списка витрин из теста (#49): 503 UPSTREAM_UNAVAILABLE или 429 RATE_LIMITED с Retry-After; null — снять. */
  failShopList(failure: ShopListFailure | null): void;
  /**
   * Обрыв ответа на POST …/orders после записи заказа (#62, РП58 п. 4): RESET — соединение закрыто без ответа, GARBLED —
   * 201 с обрезанным телом; действует до снятия (null). Сверка — чтением заказа по cart_mandate_id или номеру.
   */
  failOrderReply(failure: OrderReplyFailure | null): void;
  /**
   * Сбой ответа на POST …/payment (#92, РП58 дополнение #92): RESET_BEFORE — до приёма пакета, операции нет; RESET_AFTER,
   * GARBLED, 5XX — после авторизации, операция есть. В отличие от failOrderReply — по умолчанию однократно: срабатывает на
   * `times` применимых обращениях подряд (целое ≥ 1, по умолчанию 1), затем снимается; отказы витрины его не расходуют.
   * null — снять сбой, который ещё не сработал. В stand.calls() не пишется: журнал — приложения Платформы.
   */
  failPaymentReply(failure: PaymentReplyFailure | null, opts?: { readonly times?: number }): void;
  listen(): Promise<string>;
  close(): Promise<void>;
}

export function createMerchants(stand: Stand, opts: MerchantsStandOptions = {}): MerchantsStand {
  const shops = opts.paymentMethods ? shopsWithMethods(stand.shops, opts.paymentMethods) : stand.shops;
  const showcaseUi = showcaseSettings(opts.showcaseUi);
  const opkc = new OpkcStub(opts.decide);
  const aoiSupport = opts.aoiSupport ?? true;
  const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport, opkc, now: stand.now });
  const submitted: PackageMetadata[] = [];
  const replies: { readonly statusCode: number; readonly body: unknown }[] = [];
  // Эквайрер стенда присылает метаданные Платформе по ПИ-8 (РП57 п. 5, 7): без поддержки aoi — без признака. Локальный
  // список — как прежде, только при эквайрере без aoi; ответы сверки Платформы — reconciliationReplies.
  const reconciliation: ReconciliationPort = {
    submit: async (m) => {
      if (!aoiSupport) submitted.push(m);
      const { aoi, ...rest } = m;
      replies.push(
        await stand.acquirerParticipant.submitPaymentMetadata(m.merchant_id, {
          ...rest,
          ...(aoiSupport ? { aoi: { agent_code: aoi.agent_code, mandate_id: aoi.mandate_id } } : {}),
        }),
      );
    },
  };
  const verifier = new MerchantAgentVerifier(() => stand.keys.jwks("sandbox"), {
    maxAgeMs: opts.jwksMaxAgeMs ?? stand.params.merchant_jwks_max_age_sec * 1000,
    refetchMinMs: opts.jwksRefetchMinMs ?? stand.params.merchant_jwks_refetch_min_sec * 1000,
    skewSec: stand.params.signature_skew_sec,
    now: stand.now,
  });
  // Сбои витрин демо-стенда (РП75 п. 2–3): только у стенда с режимом сбоев — его журнал и его включённые сбои. «Только
  // действия» (дополнение #115 п. 2): сбои витрин не подключаются, остаётся продление удержания.
  const demo = demoFaultsOf(stand.demo);
  const faults: MerchantFaultPort | undefined = demo && {
    active: (test, shop) => demo.on && demo.armedFor(test, shop),
    fired: (test, what, ids) => {
      if (!demo.on) throw new Error("demo: сбои витрин выключены (РП75 дополнение #115)");
      demo.fired(test, what, ids);
    },
    // «Напомнить клиенту» (РП75 п. 6) продлевает и удержание заказа у витрины.
    holdExtensionMs: (merchant_id, order_id) => demo.holdExtensionMs(merchant_id, order_id),
  };
  let shopListFailure: ShopListFailure | null = null;
  let orderReplyFailure: OrderReplyFailure | null = null;
  // Взведённый сбой ответа на оплату и остаток срабатываний (дополнение #92 п. 2).
  let paymentFailure: { readonly failure: PaymentReplyFailure; left: number } | null = null;
  const takePaymentFailure = (stage: "BEFORE" | "AFTER"): PaymentReplyFailure | null => {
    if (!paymentFailure || (stage === "BEFORE") !== (paymentFailure.failure === "RESET_BEFORE")) return null;
    const { failure } = paymentFailure;
    if (--paymentFailure.left === 0) paymentFailure = null;
    return failure;
  };
  const app = buildMerchantsServer({
    verifier,
    acquirer,
    reconciliation,
    rateLimitPerMin: opts.rateLimitPerMin ?? stand.params.merchant_rate_limit_per_min,
    orderHoldSec: stand.params.order_hold_sec,
    shopListFailure: () => shopListFailure,
    orderReplyFailure: () => orderReplyFailure,
    paymentReplyFailure: takePaymentFailure,
    now: stand.now,
    shops,
    ...(faults ? { faults } : {}),
  });
  // Человеческий вид витрин (РП58 дополнение З12) — только у сервера витрин стенда, после его маршрутов /v1 и лимита.
  registerShowcase(app, { shops, settings: showcaseUi, now: stand.now });
  return {
    app,
    acquirer,
    opkc,
    reconciliation: submitted,
    reconciliationReplies: replies,
    verifier,
    failShopList: (failure) => void (shopListFailure = failure),
    failOrderReply: (failure) => void (orderReplyFailure = failure),
    failPaymentReply(failure, o = {}) {
      if (failure === null) {
        paymentFailure = null;
        return;
      }
      // Неизвестный вид или times не целое ≥ 1 — исключение, сбой не взводится (как настройки arm, РП75).
      if (!(PAYMENT_REPLY_FAILURES as readonly string[]).includes(failure)) {
        throw new Error(`failPaymentReply: неизвестный сбой ${String(failure)}`);
      }
      const times = o.times ?? 1;
      if (!Number.isSafeInteger(times) || times < 1) throw new Error("failPaymentReply: times — целое ≥ 1");
      paymentFailure = { failure, left: times };
    },
    async listen() {
      await app.listen({ host: "127.0.0.1", port: 0 });
      const addr = app.server.address();
      if (!addr || typeof addr === "string") throw new Error("нет адреса сервера витрин");
      return `http://127.0.0.1:${addr.port}`;
    },
    close: () => app.close(),
  };
}
