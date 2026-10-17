// Стенд Платформы для тестов агента (РП25): среда dev (в одном процессе внутри теста агента),
// контур ключей sandbox (ed25519, РП23). Песочницей (средой sandbox) не является; приёмку не заменяет.
// Тестовый интерфейс, не публичный контракт: публичный контракт для агентов — только ПАО (инвариант 10).
// Оператор при допуске — от вызывающего: обход расхождения №9 допустим только здесь. Рабочий сервер
// (src/main.ts и его граф импортов) этот модуль не импортирует — проверяет tests/unit/stand-boundary.test.ts.
import type { FastifyInstance } from "fastify";
import { ConsentJournal, MemoryConsentStore } from "../consent/index.js";
import { paoIdempotency } from "../pao/idempotency.js";
import { PaoRequestVerifier } from "../pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore, type AdmissionDecision } from "../registry/index.js";
import { buildServer } from "../server.js";
import { loadParams, type Params } from "../shared/config.js";

export interface Stand {
  readonly params: Params;
  readonly registry: AgentRegistry;
  readonly keys: AgentKeys;
  readonly app: FastifyInstance;
  /** Подставляемые часы реестра, ключей и проверки подписи; undefined — системные. */
  setClock(d: Date | undefined): void;
  /** Текущее время стенда — те же часы, что у реестра и эмуляторов. */
  now(): Date;
  /** Допуск по заявлению (РП21, РП23) в контуре sandbox; оператор — от вызывающего (только стенд, №9). */
  admit(application: unknown, operator: string): AdmissionDecision;
  /** Запуск на 127.0.0.1 и свободном порту; возвращает базовый адрес для клиента ПАО. */
  listen(): Promise<string>;
  close(): Promise<void>;
}

// Хранилище и проверка подписи наружу не отдаются: через хранилище тест мог бы записать агента в обход допуска
// (инвариант 5). Параметры — только config/params.stand.json Платформы или PARAMS_PATH (РП25 п. 4).
export function createStand(): Stand {
  const params = loadParams();
  let clock: Date | undefined;
  const now = (): Date => clock ?? new Date();
  const store = new InMemoryAgentRegistryStore();
  const registry = new AgentRegistry(store, { keys: params, now });
  const keys = new AgentKeys(store, { keys: params, now });
  const verifier = new PaoRequestVerifier(
    { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
    { skewSec: params.signature_skew_sec, now },
  );
  // Идемпотентность — память ядра (РП30 п. 6): стенд живёт в процессе теста агента.
  const idempotency = paoIdempotency({ ttlSec: params.idempotency_ttl_sec, now: () => now().getTime() });
  // Журнал согласий — память ядра (РП30 п. 6), часы стенда.
  const consent = new ConsentJournal(new MemoryConsentStore(), { now });
  const app = buildServer({ env: "dev", pao: { verifier, keys, idempotency, params, consent } });
  return {
    params,
    registry,
    keys,
    app,
    setClock: (d) => (clock = d),
    now,
    admit: (application, operator) => registry.admit(application, { contour: "sandbox", operator }),
    async listen() {
      await app.listen({ host: "127.0.0.1", port: 0 });
      const addr = app.server.address();
      if (!addr || typeof addr === "string") throw new Error("нет адреса сервера стенда");
      return `http://127.0.0.1:${addr.port}`;
    },
    close: () => app.close(),
  };
}

export { createMerchants, type MerchantsStand, type MerchantsStandOptions } from "./merchants.js";
