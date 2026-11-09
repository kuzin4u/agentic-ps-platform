// Режим сбоев демо-стенда для пульта DEMO-2 (РП75, #112). Только createStand({ demo: { faults: true } }): без этого
// stand.demo нет. Рабочий сервер (src/main.ts, buildServer) модуль не импортирует — tests/unit/stand-boundary.test.ts.
// Журнал — коды, идентификаторы и время по часам стенда; тел, реквизитов, кодов подтверждения и текста для человека нет
// (инварианты 1, 7; правило совместимости 3).
import { AsyncLocalStorage } from "node:async_hooks";
import type { FastifyInstance, FastifyRequest } from "fastify";

/** Тесты пульта (РП75 п. 3): закрытый перечень. */
export const DEMO_TESTS = ["Н-01", "Н-02", "Н-03", "Н-04", "Н-05", "Н-06", "Н-07", "Н-08", "Н-09", "Н-10", "Н-11", "Н-12"] as const;
export type DemoTest = (typeof DEMO_TESTS)[number];

/** Вид «П» — сбой Платформы, включается arm (РП75 п. 3). */
const ARMABLE: ReadonlySet<DemoTest> = new Set(["Н-02", "Н-03", "Н-04", "Н-05", "Н-11", "Н-12"]);
/** Вид «ПР» — нарушение агента разыгрывает приложение и ставит mark (РП75 п. 3); Н-05 — оба вида. Н-10 — ни того ни другого. */
const MARKABLE: ReadonlySet<DemoTest> = new Set(["Н-01", "Н-05", "Н-06", "Н-07", "Н-08", "Н-09"]);
/** Сбой срабатывает один раз и снимается сам (РП75 п. 3). */
const ONCE: ReadonlySet<DemoTest> = new Set(["Н-02"]);

/** Идентификаторы, которые можно писать в журнал (РП75 п. 4): закрытый перечень. */
export const DEMO_ID_FIELDS = ["mandate_id", "confirmation_id", "op_ref", "merchant_id", "shop_id", "order_id", "order_ref"] as const;
export type DemoIds = Partial<Record<(typeof DEMO_ID_FIELDS)[number], string>>;

/** Настройки сбоя (РП75 п. 3): закрытый перечень полей; смысл — у сбоя. */
export const DEMO_FAULT_OPTION_FIELDS = ["merchant_id", "shop_id", "delay_ms", "reorder"] as const;
export interface DemoFaultOptions {
  readonly merchant_id?: string;
  readonly shop_id?: string;
  readonly delay_ms?: number;
  readonly reorder?: boolean;
}

/** Какие настройки принимает сбой (РП75 п. 3): у сбоев витрин — выбор витрины; без настройки — все витрины стенда. */
const OPTIONS_BY_TEST: Readonly<Partial<Record<DemoTest, readonly (typeof DEMO_FAULT_OPTION_FIELDS)[number][]>>> = {
  "Н-02": [],
  "Н-03": ["merchant_id", "shop_id"],
  "Н-04": ["merchant_id", "shop_id"],
  "Н-05": ["merchant_id", "shop_id"],
  "Н-11": [],
  "Н-12": ["delay_ms", "reorder"],
};

/**
 * Что записано (РП75 п. 4): код из закрытого перечня; коды сбоев и действий добавляют их кирпичи.
 * PAID_BEFORE_OUTCOME — Н-03, витрина ответила «оплачено», не дождавшись решения; FULFILLED_BEFORE_OUTCOME — Н-04,
 * витрина исполнила заказ до решения; INSTRUCTION_SERVED — Н-05, каталог отдан с инструкцией агенту в описании товара.
 */
export const DEMO_LOG_WHAT = [
  "ARMED",
  "DISARMED",
  "MARKED",
  "PAID_BEFORE_OUTCOME",
  "FULFILLED_BEFORE_OUTCOME",
  "INSTRUCTION_SERVED",
  "UPK_CODE_LEAKED",
  "OUTCOME_EVENT_DELAYED",
  "OUTCOME_EVENTS_REORDERED",
  "SECOND_CREDENTIAL_ISSUED",
  // Действия кнопок реакции (РП75 п. 6): PURCHASE_STOPPED — CART отозван; CONFIRMATION_REJECTED — ожидающий запрос по нему
  // отклонён банком; CLIENT_REMINDED — срок продлён; REMIND_REPEATED — повтор без продления; MANDATE_REVOKED — отзыв
  // клиентом; ACTION_REFUSED — шлюз участников отказал (ответ — как есть); SENT_TO_REVIEW — передано на разбор.
  "PURCHASE_STOPPED",
  "CONFIRMATION_REJECTED",
  "CLIENT_REMINDED",
  "REMIND_REPEATED",
  "MANDATE_REVOKED",
  "ACTION_REFUSED",
  "SENT_TO_REVIEW",
] as const;
export type DemoLogWhat = (typeof DEMO_LOG_WHAT)[number];

/** Кто нарушил — для «Передать на разбор» (РП75 п. 6): закрытый перечень. */
export const DEMO_VIOLATORS = ["AGENT", "MERCHANT", "BANK", "PLATFORM", "OPERATOR"] as const;
export type DemoViolator = (typeof DEMO_VIOLATORS)[number];

/** Условие модели пульта — код вида R46. */
const CONDITION = /^R\d{2,3}$/;

export interface DemoReview {
  readonly condition: string;
  readonly violator: DemoViolator;
}

export interface DemoLogEntry {
  readonly seq: number;
  /** Часы стенда, ISO 8601. */
  readonly at: string;
  readonly kind: "fault" | "action";
  readonly test?: DemoTest;
  readonly what: DemoLogWhat;
  readonly ids: DemoIds;
  /** Только SENT_TO_REVIEW: условие и кто нарушил. */
  readonly review?: DemoReview;
}

/** Ответ шлюза участников (ПИ-8) на действие — как есть. */
export interface DemoGatewayReply {
  readonly statusCode: number;
  readonly body: unknown;
}

/**
 * Действия кнопок реакции (РП75 п. 6): ответ — результат шлюза участников или исключение; запись в журнале — на каждый
 * вызов, дошедший до шлюза или стенда. Неверный аргумент (неизвестный мандат или запрос, не CART, не PENDING, поле вне
 * перечня) — исключение без записи, как у arm.
 */
export interface DemoActions {
  /**
   * «Остановить покупку»: отзыв CART через банк стенда (ПИ-8 revoke, как клиент в приложении банка); ожидающие запросы
   * подтверждения по CART закрывает сам отзыв (РП76: REJECTED с closed MANDATE_REVOKED). rejected — их confirmation_id.
   */
  stopPurchase(cart_mandate_id: string): Promise<DemoGatewayReply & { readonly rejected: readonly string[] }>;
  /**
   * «Напомнить клиенту»: один раз на запрос срок ожидающего запроса подтверждения и удержание заказа у витрины продлеваются
   * на confirmation_remind_extend_sec; confirmation_ref и итоговые значения не меняются (инвариант 7). Повтор — без
   * продления (extended: false), с записью.
   */
  remindClient(confirmation_id: string): Promise<{ readonly confirmation_id: string; readonly expires_at: string; readonly extended: boolean }>;
  /** «Отозвать поручение»: отзыв мандата клиентом через банк стенда (РП38, ПИ-8 revoke). */
  revokeMandate(mandate_id: string): Promise<DemoGatewayReply>;
  /** «Передать на разбор»: только запись журнала; tx — идентификаторы операции из перечня ids. */
  sendToReview(r: { readonly tx: DemoIds; readonly condition: string; readonly violator: DemoViolator }): DemoLogEntry;
}

export interface StandDemo extends DemoActions {
  /** Включить сбой вида «П»; повтор — новые настройки и новая запись. Не «П» или неизвестный код — исключение. */
  arm(test: DemoTest, opts?: DemoFaultOptions): void;
  /** Снять сбой; true — был включён (запись в журнале), false — не был (записи нет). */
  disarm(test: DemoTest): boolean;
  /** Пометка нарушения, которое разыграло приложение (вид «ПР»); иное — исключение. */
  mark(test: DemoTest, ids: DemoIds): void;
  /** Копия журнала по порядку записи. */
  log(): readonly DemoLogEntry[];
}

/** Для сборки стенда: включён ли сбой и с какими настройками; сбой «один раз» снимается при срабатывании. */
export interface DemoFaults {
  armed(test: DemoTest): DemoFaultOptions | undefined;
  /** Сбой витрины включён для этой витрины: без выбора — для всех, с выбором — только для выбранной (РП75 п. 3). */
  armedFor(test: DemoTest, shop: { readonly id: string; readonly merchant_id: string }): boolean;
  /** Сбой сработал: запись в журнале; сбой «один раз» снимается. */
  fired(test: DemoTest, what: DemoLogWhat, ids: DemoIds): void;
  /**
   * Сбой изменил ответ идущего обращения к приложению стенда — пометка `StandCall.fault` (РП75 п. 5). Вне обращения к
   * стенду (вызов метода стенда, витрины эмулятора) — ничего.
   */
  markCall(test: DemoTest): void;
  /** Продление удержания заказа у витрины действием «Напомнить клиенту» (РП75 п. 6), мс; 0 — не продлено. */
  holdExtensionMs(merchant_id: string, order_id: string): number;
}

/** Для действий режима (demo-actions.ts): запись в журнал и продление удержания у витрины. */
export interface DemoActionSink {
  acted(what: DemoLogWhat, ids: DemoIds): void;
  extendHold(merchant_id: string, order_id: string, ms: number): void;
}

/** Наибольшая задержка события итога Н-12, мс: минута — больше теста пульта не нужно. */
const DELAY_MAX_MS = 60_000;

/** Событие ленты — то, что нужно сбою Н-12: номер, тип, время записи и ссылки. */
interface FeedEvent {
  readonly event_id: string;
  readonly type: string;
  readonly at: string;
  readonly data: unknown;
}

const isOutcome = (e: FeedEvent): boolean => e.type.startsWith("operation.");
const opRefOf = (e: FeedEvent): DemoIds => {
  const op_ref = (e.data as { op_ref?: unknown } | null)?.op_ref;
  return typeof op_ref === "string" && op_ref !== "" ? { op_ref } : {};
};

/**
 * Н-12 (РП75 п. 3): лента агента с поздним событием итога. Событие не теряется (инвариант 9): страница обрывается на первом
 * задержанном событии — курсор агента его не перешагнёт. reorder — пара итогов отдаётся в обратном порядке; курсор встаёт
 * на старшее, младшее приходит ещё раз следующим чтением (доставка «не менее одного раза», повтор — по event_id).
 * delay_ms — по умолчанию defaultDelayMs (event_reorder_window_ms); время — часы стенда.
 */
export function delayedFeed<E extends FeedEvent>(
  list: (agent_code: string, after: string | undefined, limit: number) => Promise<readonly E[]>,
  faults: DemoFaults,
  now: () => Date,
  defaultDelayMs: number,
): (agent_code: string, after: string | undefined, limit: number) => Promise<readonly E[]> {
  const logged = new Set<string>();
  const released = new Set<string>();
  const once = (id: string, what: DemoLogWhat, ids: DemoIds): void => {
    if (logged.has(id)) return;
    logged.add(id);
    faults.fired("Н-12", what, ids);
  };
  return async (agent_code, after, limit) => {
    const page = await list(agent_code, after, limit);
    const o = faults.armed("Н-12");
    if (!o) return page;
    const delay = o.delay_ms ?? defaultDelayMs;
    const young = (e: E): boolean => now().getTime() - Date.parse(e.at) < delay;
    const i = page.findIndex((e) => isOutcome(e) && !released.has(e.event_id));
    if (i < 0) return page;
    const first = page[i]!;
    if (o.reorder === true) {
      const j = page.findIndex((e, k) => k > i && isOutcome(e) && !released.has(e.event_id));
      if (j < 0) {
        // Пары ещё нет: первый итог ждёт второго не дольше задержки, потом идёт как есть.
        if (!young(first)) {
          released.add(first.event_id);
          return page;
        }
        faults.markCall("Н-12");
        return page.slice(0, i);
      }
      const second = page[j]!;
      released.add(first.event_id);
      released.add(second.event_id);
      once(`${first.event_id}|${second.event_id}`, "OUTCOME_EVENTS_REORDERED", opRefOf(second));
      faults.markCall("Н-12");
      return [...page.slice(0, i), second, first];
    }
    // Задержка: старше задержки — идёт и больше не держится; первое молодое — обрыв страницы перед ним.
    for (let k = i; k < page.length; k++) {
      const e = page[k]!;
      if (!isOutcome(e) || released.has(e.event_id)) continue;
      if (!young(e)) {
        released.add(e.event_id);
        continue;
      }
      once(e.event_id, "OUTCOME_EVENT_DELAYED", opRefOf(e));
      faults.markCall("Н-12");
      return page.slice(0, k);
    }
    return page;
  };
}

/** Витрины стенда — для проверки выбора витрины в настройках сбоя. */
export interface DemoShops {
  readonly shop_ids: ReadonlySet<string>;
  readonly merchant_ids: ReadonlySet<string>;
}

// Внутренняя часть режима — только для сборки стенда (createMerchants): наружу из пакета не экспортируется.
const INTERNAL = new WeakMap<StandDemo, DemoFaults>();

/** Сбои режима этого стенда для его сборки (createMerchants); у чужого объекта — undefined. */
export function demoFaultsOf(demo: StandDemo | undefined): DemoFaults | undefined {
  return demo === undefined ? undefined : INTERNAL.get(demo);
}

const isTest = (t: unknown): t is DemoTest => typeof t === "string" && (DEMO_TESTS as readonly string[]).includes(t);

function checkTest(t: unknown): DemoTest {
  if (!isTest(t)) throw new Error(`demo: неизвестный тест ${String(t)}`);
  return t;
}

function checkIds(ids: unknown): DemoIds {
  if (ids === null || typeof ids !== "object" || Array.isArray(ids)) throw new Error("demo: ids — объект");
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(ids)) {
    if (!(DEMO_ID_FIELDS as readonly string[]).includes(k)) throw new Error(`demo: поле ids ${k} вне перечня`);
    if (typeof v !== "string" || v === "") throw new Error(`demo: ids.${k} — непустая строка`);
    out[k] = v;
  }
  return Object.freeze(out);
}

function checkOptions(test: DemoTest, opts: unknown, shops: DemoShops): DemoFaultOptions {
  if (opts === undefined) return Object.freeze({});
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) throw new Error("demo: настройки сбоя — объект");
  const allowed: readonly string[] = OPTIONS_BY_TEST[test] ?? [];
  const o = opts as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!(DEMO_FAULT_OPTION_FIELDS as readonly string[]).includes(k)) throw new Error(`demo: настройка ${k} вне перечня`);
    if (!allowed.includes(k)) throw new Error(`demo: у ${test} нет настройки ${k}`);
  }
  if (o.merchant_id !== undefined && (typeof o.merchant_id !== "string" || !shops.merchant_ids.has(o.merchant_id))) {
    throw new Error(`demo: merchant_id ${String(o.merchant_id)} — не продавец витрин стенда`);
  }
  if (o.shop_id !== undefined && (typeof o.shop_id !== "string" || !shops.shop_ids.has(o.shop_id))) {
    throw new Error(`demo: shop_id ${String(o.shop_id)} — не витрина стенда`);
  }
  if (o.delay_ms !== undefined && (!Number.isSafeInteger(o.delay_ms) || (o.delay_ms as number) < 1 || (o.delay_ms as number) > DELAY_MAX_MS)) {
    throw new Error(`demo: delay_ms — целое 1…${DELAY_MAX_MS}`);
  }
  if (o.reorder !== undefined && typeof o.reorder !== "boolean") throw new Error("demo: reorder — булево");
  return Object.freeze({ ...(o as DemoFaultOptions) });
}

/** Режим сбоев стенда: публичная часть (stand.demo) и часть для сборки стенда (сбои). */
export function createDemo(
  now: () => Date,
  shops: DemoShops,
): {
  demo: StandDemo;
  faults: DemoFaults;
  /** Контекст обращения к приложению стенда (onRequest): пометка сбоя для StandCall.fault; функция — для журнала обращений. */
  attachCalls(app: FastifyInstance): (req: FastifyRequest) => DemoTest | undefined;
  /** Подключить действия шлюза участников (после сборки банка стенда); до этого действия — исключение. */
  bindActions(make: (sink: DemoActionSink) => Omit<DemoActions, "sendToReview">): void;
} {
  const entries: DemoLogEntry[] = [];
  const armed = new Map<DemoTest, DemoFaultOptions>();
  // Продление удержания заказа у витрины (РП75 п. 6): ключ — продавец и заказ.
  const holdExtra = new Map<string, number>();
  const holdKey = (merchant_id: string, order_id: string): string => JSON.stringify([merchant_id, order_id]);
  let actions: Omit<DemoActions, "sendToReview"> | undefined;
  const bound = (): Omit<DemoActions, "sendToReview"> => {
    if (!actions) throw new Error("demo: действия не подключены");
    return actions;
  };
  // Контекст на обращение: сбой, сработавший во время обработки, помечает именно его (вложенный app.inject — своё).
  const calls = new AsyncLocalStorage<{ fault?: DemoTest }>();
  const write = (kind: DemoLogEntry["kind"], test: DemoTest | undefined, what: DemoLogWhat, ids: DemoIds, review?: DemoReview): DemoLogEntry => {
    const e: DemoLogEntry = Object.freeze({
      seq: entries.length + 1,
      at: now().toISOString(),
      kind,
      ...(test === undefined ? {} : { test }),
      what,
      ids,
      ...(review === undefined ? {} : { review }),
    });
    entries.push(e);
    return e;
  };
  const demo: StandDemo = {
    arm(test, opts) {
      const t = checkTest(test);
      if (!ARMABLE.has(t)) throw new Error(`demo: ${t} — не сбой Платформы (РП75 п. 3)`);
      armed.set(t, checkOptions(t, opts, shops));
      write("fault", t, "ARMED", Object.freeze({}));
    },
    disarm(test) {
      const t = checkTest(test);
      if (!armed.delete(t)) return false;
      write("fault", t, "DISARMED", Object.freeze({}));
      return true;
    },
    mark(test, ids) {
      const t = checkTest(test);
      if (!MARKABLE.has(t)) throw new Error(`demo: ${t} — пометка только у нарушений, которые разыгрывает приложение (РП75 п. 3)`);
      write("fault", t, "MARKED", checkIds(ids));
    },
    log: () => [...entries],
    stopPurchase: (cart_mandate_id) => bound().stopPurchase(cart_mandate_id),
    remindClient: (confirmation_id) => bound().remindClient(confirmation_id),
    revokeMandate: (mandate_id) => bound().revokeMandate(mandate_id),
    sendToReview(r) {
      if (r === null || typeof r !== "object") throw new Error("demo: разбор — объект {tx, condition, violator}");
      const tx = checkIds(r.tx);
      if (Object.keys(tx).length === 0) throw new Error("demo: tx — хотя бы один идентификатор");
      if (typeof r.condition !== "string" || !CONDITION.test(r.condition)) throw new Error("demo: condition — код вида R46");
      if (!(DEMO_VIOLATORS as readonly string[]).includes(r.violator)) throw new Error(`demo: violator ${String(r.violator)} вне перечня`);
      return write("action", undefined, "SENT_TO_REVIEW", tx, Object.freeze({ condition: r.condition, violator: r.violator }));
    },
  };
  const faults: DemoFaults = {
    armed: (test) => armed.get(test),
    armedFor(test, shop) {
      const o = armed.get(test);
      if (!o) return false;
      return (o.merchant_id === undefined || o.merchant_id === shop.merchant_id) && (o.shop_id === undefined || o.shop_id === shop.id);
    },
    fired(test, what, ids) {
      if (ONCE.has(test)) armed.delete(test);
      write("fault", test, what, checkIds(ids));
    },
    markCall(test) {
      const ctx = calls.getStore();
      if (ctx) ctx.fault = test;
    },
    holdExtensionMs: (merchant_id, order_id) => holdExtra.get(holdKey(merchant_id, order_id)) ?? 0,
  };
  INTERNAL.set(demo, faults);
  const attachCalls = (app: FastifyInstance) => {
    const byReq = new WeakMap<FastifyRequest, { fault?: DemoTest }>();
    app.addHook("onRequest", (req, _reply, done) => {
      const ctx: { fault?: DemoTest } = {};
      byReq.set(req, ctx);
      calls.run(ctx, done);
    });
    return (req: FastifyRequest) => byReq.get(req)?.fault;
  };
  const sink: DemoActionSink = {
    acted: (what, ids) => void write("action", undefined, what, checkIds(ids)),
    extendHold(merchant_id, order_id, ms) {
      const k = holdKey(merchant_id, order_id);
      holdExtra.set(k, (holdExtra.get(k) ?? 0) + ms);
    },
  };
  const bindActions = (make: (sink: DemoActionSink) => Omit<DemoActions, "sendToReview">): void => {
    if (actions) throw new Error("demo: действия уже подключены");
    actions = make(sink);
  };
  return { demo, faults, attachCalls, bindActions };
}
