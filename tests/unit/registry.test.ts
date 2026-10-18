import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ADMISSION_REFUSALS,
  AgentCodeError,
  AgentCodeTakenError,
  AgentNotFoundError,
  AgentRegistry,
  CLASSES_MATCH_PAO,
  ConcurrentChangeError,
  EXCLUSION_GROUNDS,
  InMemoryAgentRegistryStore,
  STATUSES_MATCH_PAO,
  StatusTransitionError,
  SUSPENSION_GROUNDS,
  checkTransition,
  parseAgentCode,
  type AdmissionContext,
  type AdmissionDecision,
  type AgentKey,
  type AgentRecord,
  type AgentRegistryStore,
  type AgentStatus,
  type Contour,
  type KeyPolicy,
  DEFAULT_KEY_ALGORITHMS,
  ED25519,
} from "../../src/registry/index.js";

const NOW = new Date("2026-10-10T12:00:00Z");
const KEYS: KeyPolicy = { key_ttl_days: 90, key_overlap_days: 7 };
const opts = { keys: KEYS, now: () => NOW };
const fresh = (): AgentRegistry => new AgentRegistry(new InMemoryAgentRegistryStore(), opts);
// Контур оператора принимает ГОСТ после точки расширения РП5; до неё в тестах логики допуска — ed25519 вместо ГОСТ.
const freshFor = (contour: Contour): AgentRegistry =>
  contour === "operator"
    ? new AgentRegistry(new InMemoryAgentRegistryStore(), {
        ...opts,
        algorithms: { ...DEFAULT_KEY_ALGORITHMS, operator: [ED25519] },
      })
    : fresh();

/** Открытый ключ ed25519, DER SPKI base64 — пару генерирует оператор агента (РП23 п. 2). */
const newPublicKey = (): string =>
  generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");

/** Заявление оператора BuyerAgent (ПС01); оператор — в контексте вызова, не в заявлении. */
const buyerApplication = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  agent_code: "nspk:agent:buyref-01:v3",
  class: "BUYER",
  model: "buyer-agent-ref",
  runtime: "node-20",
  alg: "ed25519",
  public_key: newPublicKey(),
  ...over,
});

const OPERATOR = "buyref-operator";
const ctx = (contour: Contour = "sandbox", operator = OPERATOR): AdmissionContext => ({ contour, operator });

const refused = (d: AdmissionDecision): readonly string[] => {
  expect(d.admitted).toBe(false);
  return d.admitted ? [] : d.reasons;
};

const admitted = (d: AdmissionDecision): AgentRecord => {
  expect(d).toMatchObject({ admitted: true });
  return (d as { record: AgentRecord }).record;
};

describe("код агента (РП21 п. 1)", () => {
  it("сторона из нескольких частей, идентификатор, версия", () => {
    expect(parseAgentCode("nspk:agent:buyref-01:v3")).toEqual({
      code: "nspk:agent:buyref-01:v3",
      issuer: "nspk:agent",
      id: "buyref-01",
      version: 3,
    });
    expect(parseAgentCode("bank-1:shop-bot:v12")).toMatchObject({
      issuer: "bank-1",
      id: "shop-bot",
      version: 12,
    });
  });

  it.each([
    "buyref-01:v3",
    "nspk:agent:buyref-01",
    "nspk:agent:buyref-01:v0",
    "nspk:agent:buyref-01:v03",
    "nspk:agent:buyref-01:3",
    "nspk:Agent:buyref-01:v3",
    "nspk::buyref-01:v3",
    "nspk:agent:buy ref:v3",
    "nspk:agent:buyref-01:v3:",
    "",
  ])("не по грамматике: %j — отказ", (c) => {
    expect(() => parseAgentCode(c)).toThrow(AgentCodeError);
  });

  it("не строка — отказ", () => {
    for (const v of [null, undefined, 3, {}, ["nspk", "agent", "x", "v1"]])
      expect(() => parseAgentCode(v)).toThrow(AgentCodeError);
  });
});

describe("ПС01 (часть реестра): допуск оператора BuyerAgent по заявлению", () => {
  it("агент ACTIVE, класс BUYER, уровень 1", () => {
    const reg = fresh();
    const rec = admitted(reg.admit(buyerApplication(), ctx()));
    expect(rec).toMatchObject({
      agent_code: "nspk:agent:buyref-01:v3",
      issuer: "nspk:agent",
      id: "buyref-01",
      version: 3,
      operator: OPERATOR,
      class: "BUYER",
      level: 1,
      status: "ACTIVE",
      status_ground: null,
      contour: "sandbox",
      conformance_run_ref: null,
      admitted_at: NOW.toISOString(),
      row_version: 1,
    });
    expect(reg.get("nspk:agent:buyref-01:v3")).toEqual(rec);
    expect(Object.isFrozen(rec)).toBe(true);
  });

  it("уровень, статус и оператор из заявления не берутся (инвариант 5)", () => {
    const rec = admitted(fresh().admit(buyerApplication({ level: 9, status: "SUSPENDED", operator: "evil" }), ctx()));
    expect(rec).toMatchObject({ level: 1, status: "ACTIVE", operator: OPERATOR });
  });

  it("в записи только поля реестра: поля вне белого списка не попадают (A2 п. 1.2)", () => {
    const rec = admitted(
      fresh().admit(buyerApplication({ comment: "x", principal_ref: "P-1", cardholder_name: "x", fio: "x" }), ctx()),
    );
    expect(Object.keys(rec).sort()).toEqual(
      [
        "admitted_at",
        "agent_code",
        "class",
        "conformance_run_ref",
        "contour",
        "id",
        "issuer",
        "level",
        "model",
        "operator",
        "row_version",
        "runtime",
        "status",
        "status_changed_at",
        "status_ground",
        "version",
      ].sort(),
    );
  });

  it("нет оператора в контексте или неизвестный контур — исключение вызывающему, не отказ заявителю", () => {
    expect(() => fresh().admit(buyerApplication(), ctx("sandbox", " "))).toThrow();
    expect(() => fresh().admit(buyerApplication(), ctx("prod" as Contour))).toThrow();
  });
});

describe("основания отказа — закрытый перечень (РП21 п. 2)", () => {
  const card = (x: Record<string, unknown>): Record<string, unknown> => ({
    agent_card: { "x-system": { agent_code: "nspk:agent:buyref-01:v3", class: "BUYER", ...x } },
  });
  // Цифровые строки не проходят проверку Луна: номера карты в тестах нет (инвариант 1).
  const x25519PublicKey = (): string =>
    generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const cases: [string, Record<string, unknown>, Contour][] = [
    ["APPLICATION_INCOMPLETE", { model: undefined }, "sandbox"],
    ["APPLICATION_INCOMPLETE", { model: "  " }, "sandbox"],
    ["APPLICATION_INCOMPLETE", { runtime: 7 }, "sandbox"],
    ["APPLICATION_INCOMPLETE", { agent_code: undefined }, "sandbox"],
    ["CLASS_UNKNOWN", { class: "BUYER_PLUS" }, "sandbox"],
    ["CLASS_UNKNOWN", { class: undefined }, "sandbox"],
    ["CODE_INVALID", { agent_code: "buyref-01" }, "sandbox"],
    ["PRINCIPAL_DATA", { model: "ivan@mail.ru" }, "sandbox"],
    ["PRINCIPAL_DATA", { runtime: "node +7 916 123-45-67" }, "sandbox"],
    ["PRINCIPAL_DATA", { model: "8 (916) 123 45 67" }, "sandbox"],
    ["PRINCIPAL_DATA", { runtime: "1111 1111 1111 1111" }, "sandbox"],
    ["PRINCIPAL_DATA", { model: "x-1111111111111111" }, "sandbox"],
    ["PRINCIPAL_DATA", card({ principal_type: "Иванов И.И." }), "sandbox"],
    ["PRINCIPAL_DATA", card({ principal: { name: "x" } }), "sandbox"],
    ["PRINCIPAL_DATA", card({ cardholderName: "x" }), "sandbox"],
    ["PRINCIPAL_DATA", card({ source: { contact: "ivan@mail.ru" } }), "sandbox"],
    ["CONFORMANCE_MISSING", {}, "operator"],
    ["CONFORMANCE_MISSING", { conformance_run_ref: "" }, "operator"],
    ["CONFORMANCE_MISSING", { conformance_run_ref: 5 }, "operator"],
    ["AGENT_CARD_MISMATCH", card({ agent_code: "nspk:agent:other:v1" }), "sandbox"],
    ["AGENT_CARD_MISMATCH", card({ class: "SELLER" }), "sandbox"],
    ["AGENT_CARD_MISMATCH", { agent_card: {} }, "sandbox"],
    ["APPLICATION_INCOMPLETE", { alg: undefined }, "sandbox"],
    ["APPLICATION_INCOMPLETE", { public_key: undefined }, "sandbox"],
    ["CODE_INVALID", { agent_code: "bank-1:shop-bot:v1" }, "sandbox"],
    ["CODE_INVALID", { agent_code: "nspk:buyref-01:v3" }, "sandbox"],
    ["KEY_INVALID", { alg: "rsa" }, "sandbox"],
    ["KEY_INVALID", { alg: "ED25519" }, "sandbox"],
    ["KEY_INVALID", { alg: 5 }, "sandbox"],
    ["KEY_INVALID", { public_key: "" }, "sandbox"],
    ["KEY_INVALID", { public_key: "not base64!" }, "sandbox"],
    ["KEY_INVALID", { public_key: "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=" }, "sandbox"],
    ["KEY_INVALID", { public_key: x25519PublicKey() }, "sandbox"],
    ["KEY_INVALID", { public_key: Buffer.alloc(32, 7).toString("base64") }, "sandbox"],
  ];

  const build = (over: Record<string, unknown>): Record<string, unknown> => {
    const app = buyerApplication();
    for (const [k, v] of Object.entries(over)) {
      if (v === undefined) delete app[k];
      else app[k] = v;
    }
    return app;
  };

  it.each(cases)("%s: %j в контуре %s — ровно это основание", (reason, over, contour) => {
    expect(refused(freshFor(contour).admit(build(over), ctx(contour)))).toEqual([reason]);
  });

  it("каждое основание перечня покрыто случаем с точным набором оснований", () => {
    const seen = new Set<string>(cases.map(([r]) => r));
    seen.add("CODE_TAKEN");
    expect([...seen].sort()).toEqual([...ADMISSION_REFUSALS].sort());
  });

  const oauthCard = (): Record<string, unknown> => {
    const c = card({ principal: "LEGAL_ENTITY", knowledge_source: "catalog" });
    (c.agent_card as Record<string, unknown>).securitySchemes = { oauth: { flows: { clientCredentials: {} } } };
    return c;
  };

  it.each([
    ["поля вне белого списка", { operator_inn: "7700000000", ip_address: "10.0.0.1", principal_ref: "P-1" }],
    ["тип принципала в Agent Card", card({ principal_type: "INDIVIDUAL" })],
    ["OAuth в стандартной части Agent Card", oauthCard()],
    ["модель с датой и версия среды", { model: "model-2024-08-06", runtime: "node-20.19.0" }],
  ])("без оснований — допуск: %s (A6 п. 2.1)", (_name, over) => {
    admitted(fresh().admit(build(over), ctx()));
  });

  it("CODE_TAKEN: тот же код повторно", () => {
    const reg = fresh();
    admitted(reg.admit(buyerApplication(), ctx()));
    expect(refused(reg.admit(buyerApplication(), ctx()))).toEqual(["CODE_TAKEN"]);
  });

  it("CODE_TAKEN: новая версия чужого агента, оператор в теле не помогает; своя новая версия — новая запись", () => {
    const reg = fresh();
    admitted(reg.admit(buyerApplication(), ctx()));
    const v4 = buyerApplication({ agent_code: "nspk:agent:buyref-01:v4" });
    expect(refused(reg.admit(v4, ctx("sandbox", "someone-else")))).toEqual(["CODE_TAKEN"]);
    expect(refused(reg.admit({ ...v4, operator: OPERATOR }, ctx("sandbox", "someone-else")))).toEqual(["CODE_TAKEN"]);
    expect(admitted(reg.admit(v4, ctx())).version).toBe(4);
    expect(reg.get("nspk:agent:buyref-01:v3")?.version).toBe(3);
  });

  it("CODE_INVALID и CODE_TAKEN — разные основания", () => {
    const reg = fresh();
    admitted(reg.admit(buyerApplication(), ctx()));
    expect(refused(reg.admit(buyerApplication({ agent_code: "nspk:agent:buyref-01:3" }), ctx()))).toEqual([
      "CODE_INVALID",
    ]);
  });

  it("все применимые основания сразу", () => {
    const reasons = refused(fresh().admit({ agent_code: "x", class: "BOT", model: "a@b.ru" }, ctx("operator")));
    expect([...reasons].sort()).toEqual(
      ["APPLICATION_INCOMPLETE", "CLASS_UNKNOWN", "CODE_INVALID", "CONFORMANCE_MISSING", "PRINCIPAL_DATA"].sort(),
    );
  });

  it("не объект — отказ по перечню, не исключение", () => {
    for (const v of [null, "x", 3, []]) {
      expect(refused(fresh().admit(v, ctx()))).toEqual(["APPLICATION_INCOMPLETE", "CLASS_UNKNOWN"]);
    }
  });

  it.each(["", 5, "RUN-77"])("песочница: conformance_run_ref %j не учитывается и не записывается (РП17)", (ref) => {
    const rec = admitted(fresh().admit(buyerApplication({ conformance_run_ref: ref }), ctx()));
    expect(rec.conformance_run_ref).toBeNull();
  });

  it("CODE_TAKEN неделим с вставкой: хранилище само отказывает при чужом владельце", () => {
    const store = new InMemoryAgentRegistryStore();
    const d = new AgentRegistry(store, opts).admit(buyerApplication(), ctx());
    const rec = admitted(d);
    const key = (d as { key: AgentKey }).key;
    expect(store.ownerOf("nspk:agent", "buyref-01")).toBe(OPERATOR);
    const v4 = { ...rec, agent_code: "nspk:agent:buyref-01:v4", version: 4, operator: "x" };
    expect(() => store.insert(v4, { ...key, kid: "other", agent_code: v4.agent_code })).toThrow(AgentCodeTakenError);
    expect(() => store.insert(rec, key)).toThrow(AgentCodeTakenError);
  });

  it("контур оператора с прогоном набора — допуск, ссылка в записи (РП17)", () => {
    const rec = admitted(
      freshFor("operator").admit(buyerApplication({ conformance_run_ref: "RUN-77" }), ctx("operator")),
    );
    expect(rec).toMatchObject({ contour: "operator", conformance_run_ref: "RUN-77" });
  });

  it("поля заявления из прототипа не учитываются", () => {
    const app = Object.create(buyerApplication()) as Record<string, unknown>;
    expect(refused(fresh().admit(app, ctx()))).toContain("APPLICATION_INCOMPLETE");
  });

  it("одинаковые условия: исход не зависит от оператора (A6 п. 2.1, РП17)", () => {
    const strip = (r: AgentRecord): Record<string, unknown> => ({ ...r, operator: "" });
    const base = strip(admitted(fresh().admit(buyerApplication(), ctx())));
    for (const operator of ["third-party-ltd", "bank-42"]) {
      expect(strip(admitted(fresh().admit(buyerApplication(), ctx("sandbox", operator))))).toEqual(base);
    }
  });
});

describe("статус допуска (РП21 п. 4)", () => {
  const admittedReg = (): AgentRegistry => {
    const reg = fresh();
    admitted(reg.admit(buyerApplication(), ctx()));
    return reg;
  };
  const CODE = "nspk:agent:buyref-01:v3";

  it.each(SUSPENSION_GROUNDS)("ACTIVE → SUSPENDED (%s) → ACTIVE", (ground) => {
    const reg = admittedReg();
    expect(reg.changeStatus(CODE, { to: "SUSPENDED", ground })).toMatchObject({
      status: "SUSPENDED",
      status_ground: ground,
    });
    expect(reg.changeStatus(CODE, { to: "ACTIVE" })).toMatchObject({
      status: "ACTIVE",
      status_ground: null,
    });
  });

  it.each(EXCLUSION_GROUNDS)("EXCLUDED (%s) — из любого статуса, выхода нет", (ground) => {
    for (const suspendFirst of [false, true]) {
      const reg = admittedReg();
      if (suspendFirst) reg.changeStatus(CODE, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
      expect(reg.changeStatus(CODE, { to: "EXCLUDED", ground })).toMatchObject({
        status: "EXCLUDED",
        status_ground: ground,
      });
      for (const change of [
        { to: "ACTIVE" },
        { to: "SUSPENDED", ground: "KEY_COMPROMISE" },
        { to: "EXCLUDED", ground },
      ]) {
        expect(() => reg.changeStatus(CODE, change)).toThrow(StatusTransitionError);
      }
    }
  });

  it.each([
    [{ to: "SUSPENDED" }],
    [{ to: "SUSPENDED", ground: "WITHDRAWN" }],
    [{ to: "SUSPENDED", ground: "BAD_MOOD" }],
    [{ to: "ACTIVE" }],
    [{ to: "ACTIVE", ground: "KEY_COMPROMISE" }],
    [{ to: "EXCLUDED" }],
    [{ to: "PAUSED", ground: "KEY_COMPROMISE" }],
    [null],
    ["SUSPENDED"],
  ])("недопустимый переход из ACTIVE: %j — отказ", (change) => {
    expect(() => admittedReg().changeStatus(CODE, change)).toThrow(StatusTransitionError);
  });

  it("основание из прототипа не принимается", () => {
    const change = Object.create({ ground: "KEY_COMPROMISE" }) as Record<string, unknown>;
    change.to = "SUSPENDED";
    expect(() => admittedReg().changeStatus(CODE, change)).toThrow(StatusTransitionError);
  });

  it("SUSPENDED → SUSPENDED — отказ", () => {
    const reg = admittedReg();
    reg.changeStatus(CODE, { to: "SUSPENDED", ground: "OUT_OF_MANDATE" });
    expect(() => reg.changeStatus(CODE, { to: "SUSPENDED", ground: "OUT_OF_MANDATE" })).toThrow(StatusTransitionError);
  });

  it("нет агента — исключение", () => {
    expect(() => fresh().changeStatus(CODE, { to: "ACTIVE" })).toThrow(AgentNotFoundError);
  });

  it("конкурентное изменение: проверка по версии строки, ABA не проходит", () => {
    const store = new InMemoryAgentRegistryStore();
    const reg = new AgentRegistry(store, opts);
    const rec = admitted(reg.admit(buyerApplication(), ctx()));
    expect(rec.row_version).toBe(1);
    // Пока первый читатель держит запись с версией 1, второй успевает ACTIVE → SUSPENDED → ACTIVE.
    reg.changeStatus(CODE, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    reg.changeStatus(CODE, { to: "ACTIVE" });
    expect(store.get(CODE)?.status).toBe("ACTIVE");
    expect(
      store.updateStatus(CODE, rec.row_version, {
        status: "EXCLUDED",
        status_ground: "WITHDRAWN",
        status_changed_at: "x",
      }),
    ).toBeUndefined();
    expect(store.get(CODE)).toMatchObject({ status: "ACTIVE", row_version: 3 });
    const stale: AgentRegistryStore = {
      ...store,
      get: () => rec,
      agentCodes: () => [],
      ownerOf: () => undefined,
      insert: () => undefined,
      updateStatus: (c, v, f) => store.updateStatus(c, v, f),
      getKey: () => undefined,
      keysOf: () => [],
      addKey: () => false,
      revokeKey: () => undefined,
      subscriptionOf: () => undefined,
      setSubscription: () => false,
    };
    expect(() =>
      new AgentRegistry(stale, opts).changeStatus(CODE, { to: "EXCLUDED", ground: "WITHDRAWN" }),
    ).toThrow(ConcurrentChangeError);
  });

  it("смена статуса меняет только поля статуса", () => {
    const store = new InMemoryAgentRegistryStore();
    const reg = new AgentRegistry(store, opts);
    admitted(reg.admit(buyerApplication(), ctx()));
    const before = store.get(CODE) as AgentRecord;
    const after = reg.changeStatus(CODE, { to: "SUSPENDED", ground: "OUT_OF_MANDATE" });
    const STATUS_FIELDS = new Set(["status", "status_ground", "status_changed_at", "row_version"]);
    const rest = (r: AgentRecord): Record<string, unknown> =>
      Object.fromEntries(Object.entries(r).filter(([k]) => !STATUS_FIELDS.has(k)));
    expect(rest(after)).toEqual(rest(before));
  });

  it("неизвестный текущий статус — переход запрещён (инвариант 3)", () => {
    expect(() => checkTransition("PAUSED" as AgentStatus, { to: "EXCLUDED", ground: "WITHDRAWN" })).toThrow(
      StatusTransitionError,
    );
  });

  it("запись в хранилище не меняется снаружи", () => {
    const reg = admittedReg();
    const rec = reg.get(CODE) as AgentRecord;
    expect(() => {
      (rec as { level: number }).level = 5;
    }).toThrow(TypeError);
  });
});

describe("перечни совпадают с ПАО", () => {
  it("классы и статусы — AgentSelf", () => {
    expect(CLASSES_MATCH_PAO).toBe(true);
    expect(STATUSES_MATCH_PAO).toBe(true);
  });
});
