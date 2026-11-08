// Режим сбоев демо-стенда для пульта DEMO-2 (РП75, #112). Только createStand({ demo: { faults: true } }): без этого
// stand.demo нет. Рабочий сервер (src/main.ts, buildServer) модуль не импортирует — tests/unit/stand-boundary.test.ts.
// Журнал — коды, идентификаторы и время по часам стенда; тел, реквизитов, кодов подтверждения и текста для человека нет
// (инварианты 1, 7; правило совместимости 3).

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
] as const;
export type DemoLogWhat = (typeof DEMO_LOG_WHAT)[number];

export interface DemoLogEntry {
  readonly seq: number;
  /** Часы стенда, ISO 8601. */
  readonly at: string;
  readonly kind: "fault" | "action";
  readonly test?: DemoTest;
  readonly what: DemoLogWhat;
  readonly ids: DemoIds;
}

export interface StandDemo {
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
  return Object.freeze({ ...(o as DemoFaultOptions) });
}

/** Режим сбоев стенда: публичная часть (stand.demo) и часть для сборки стенда (сбои). */
export function createDemo(now: () => Date, shops: DemoShops): { demo: StandDemo; faults: DemoFaults } {
  const entries: DemoLogEntry[] = [];
  const armed = new Map<DemoTest, DemoFaultOptions>();
  const write = (kind: DemoLogEntry["kind"], test: DemoTest | undefined, what: DemoLogWhat, ids: DemoIds): void => {
    entries.push(
      Object.freeze({ seq: entries.length + 1, at: now().toISOString(), kind, ...(test === undefined ? {} : { test }), what, ids }),
    );
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
  };
  INTERNAL.set(demo, faults);
  return { demo, faults };
}
