// Стенд Платформы для тестов агента (РП25): среда dev (в одном процессе внутри теста агента),
// контур ключей sandbox (ed25519, РП23). Песочницей (средой sandbox) не является; приёмку не заменяет.
// Тестовый интерфейс, не публичный контракт: публичный контракт для агентов — только ПАО (инвариант 10).
// Оператор при допуске — от вызывающего: обход расхождения №9 допустим только здесь. Рабочий сервер
// (src/main.ts и его граф импортов) этот модуль не импортирует — проверяет tests/unit/stand-boundary.test.ts.
import type { FastifyInstance } from "fastify";
import { Adp, MemoryOperationStore } from "../adp/index.js";
import { ConsentJournal, MemoryConsentStore } from "../consent/index.js";
import type { MandateDecisionPayload } from "../consent/model.js";
import { createAgentReceiver, type AgentReceiver } from "../env/agent/index.js";
import { createIssuerEmulator } from "../env/issuer/index.js";
import { EventDeliverer, type DeliveryRow } from "../pao/delivery.js";
import { MemoryLimitsStore, type LimitsRecord } from "../participants/limits.js";
import { MemoryParticipantNotificationStore, ParticipantNotifier, type NotifierResult } from "../participants/notifications.js";
import { TrustedParticipants, type TrustedParticipantKey } from "../participants/trusted.js";
import { ParticipantRequestVerifier } from "../participants/verify.js";
import { paoIdempotency } from "../pao/idempotency.js";
import { PaoRequestVerifier } from "../pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore, type AdmissionDecision } from "../registry/index.js";
import { buildServer } from "../server.js";
import { loadParams, type Params } from "../shared/config.js";
import { holdLedger, StateService } from "../state/index.js";
import { createStandDns, type StandDns } from "./dns.js";

/** Решение клиента в приложении банка стенда; по умолчанию — подпись простой ЭП с согласием на токен (РП12). */
export interface IssuerSignOptions {
  readonly decision?: MandateDecisionPayload["decision"];
  readonly signature_type?: MandateDecisionPayload["signature_type"];
  readonly token_consent?: boolean;
}

/** Эмулятор эмитента стенда (РП36 п. 4): подписывает тестовым ключом и шлёт тот же POST /participants/v1/mandates/{id}/sign. */
export interface StandIssuer {
  readonly participant_code: string;
  /** Открытый ключ банка стенда: проверка подписей банка в выписке без Платформы (РП38 п. 7). */
  readonly trustedKey: TrustedParticipantKey;
  /** Ответ шлюза участников: 200 `{mandate_id, status}` или `{code}`; неизвестный мандат — 404 без обращения. */
  sign(mandateId: string, opts?: IssuerSignOptions): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /** Отзыв мандата клиентом в приложении банка (РП38): ответ шлюза участников, неизвестный — 404 без обращения. */
  revoke(mandateId: string): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /**
   * Лимиты клиента в приложении банка (РП45 п. 1, ПИ-8 `PUT /participants/v1/principals/{ref}/limits`): подписанная
   * запись версии version; ответ шлюза участников — 200 `{principal_ref, version}` или `{code}`.
   */
  setLimits(principalRef: string, limits: unknown, version: number): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /** Чтение действующей записи лимитов (ПИ-8 `GET …/limits`) с подписью запроса банка (RFC 9421, РП46 (в)). */
  getLimits(principalRef: string): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /** Заголовки подписанного запроса банка без тела (RFC 9421) — для своих чтений ПИ-8 и тестов отказов. */
  signRequest(method: string, path: string, query: string, at: Date): Record<string, string>;
  /**
   * Отзыв всех полномочий клиента одним действием в приложении банка (РП45 п. 4, РП46 (а); ПИ-8 `revoke-all`): ответ —
   * 200 `{principal_ref, revocation_ref, revoked}` или `{code}`; `mandate.revoked` агенту — по каждому мандату.
   */
  revokeAll(principalRef: string, revocationRef: string): Promise<{ readonly statusCode: number; readonly body: unknown }>;
}

export interface Stand {
  readonly params: Params;
  readonly registry: AgentRegistry;
  readonly keys: AgentKeys;
  readonly app: FastifyInstance;
  /** Разрешение имени стенда для адреса подписки (РП40 п. 8): подмена DNS в тестах. */
  readonly dns: StandDns;
  /** Эмулятор агента-получателя push-событий (ПС23): ответы по очереди, полученные и обработанные события. */
  readonly agentReceiver: AgentReceiver;
  /**
   * Проход доставки по часам стенда (РП40 п. 5): все готовые попытки до пустой очереди; число попыток. Повтор
   * наступает по nextAttemptDelayMs ядра — тест двигает часы стенда (setClock). Таймера на стенде нет.
   */
  deliverEvents(): Promise<number>;
  /** Строка попытки push по событию (состояние, попытки, причина) — для тестов. */
  delivery(event_id: string): Promise<DeliveryRow | undefined>;
  /**
   * Проход уведомителя участников по часам стенда (РП46 доп. п. 7): уведомления клиента через банк по решённым записям
   * операций ADP вне пути авторизации. Таймера на стенде нет — тест вызывает проход сам.
   */
  notifyParticipants(): Promise<NotifierResult>;
  /** Приложение банка: подпись и отзыв мандата клиентом (РП12, РП36, РП38). */
  readonly issuer: StandIssuer;
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
  // Банк стенда — эмулятор эмитента с ключом в памяти; другого доверенного участника на стенде нет (РП36 доп.).
  const emulator = createIssuerEmulator();
  const trusted = new TrustedParticipants([emulator.trustedKey], { stand: true });
  // Push по событию — только ACTIVE-агенту, подписанному на тип, на момент записи (РП40 п. 5–6).
  const consentStore = new MemoryConsentStore();
  const consent: ConsentJournal = new ConsentJournal(consentStore, {
    now,
    revocationOrder: () => trusted.revocationOrder(),
    pushFor: (code, type) => registry.get(code)?.status === "ACTIVE" && (registry.subscription(code)?.events.includes(type) ?? false),
    amountLeft: (id, limit) => state.amountLeft(id, limit),
  });
  // Лимиты клиента от банка (РП45 п. 1): в памяти, как журнал стенда.
  const limits = new MemoryLimitsStore();
  // Бюджет мандата (П3, РП41): удержания ядра в памяти, часы стенда; проход expire — без таймера (как доставка событий).
  const state: StateService = new StateService(holdLedger(), consent, {
    reservationTtlSec: params.reservation_ttl_sec,
    now,
    exhausted: (id, payload) => consent.exhausted(id, payload),
  });
  // Подписка — в записи агента (РП40 п. 1); разрешение имени — стендовое, проверка адреса та же, что в рабочем сервере (п. 8).
  const dns = createStandDns();
  const subscriptions = { set: registry.subscribe.bind(registry) };
  const agentReceiver = createAgentReceiver();
  const deliverer = new EventDeliverer({
    store: consentStore,
    agent: (c) => registry.get(c),
    subscription: (c) => registry.subscription(c),
    resolveHost: dns.resolve,
    transport: agentReceiver.transport,
    params,
    now: () => now().getTime(),
    stand: true,
  });
  // Записи операций ADP стенда — память; уведомитель участников читает их вне пути авторизации (РП46 доп. п. 7).
  const operations = new MemoryOperationStore();
  const notifications = new MemoryParticipantNotificationStore(operations);
  const notifier = new ParticipantNotifier(notifications, {
    horizonSec: params.participant_notify_horizon_sec,
    now: () => now().getTime(),
  });
  const app = buildServer({
    env: "dev",
    pao: { verifier, keys, idempotency, params, consent, subscriptions, resolveHost: dns.resolve, stand: true },
    participants: { trusted, consent, params, state, limits, now, requests: new ParticipantRequestVerifier(trusted, { skewSec: params.signature_skew_sec, now }) },
    // ADP стенда (ПИ-1, РП43): реестр, журнал и П3 стенда, записи операций в памяти; только 127.0.0.1 (доп. РП43 п. 21).
    // Мандат — с клиентом из журнала, лимиты клиента — из записей банка стенда (РП45 п. 1–2).
    adp: {
      adp: new Adp({
        agents: registry,
        mandates: { get: (id, agent_code) => consent.adpMandate(id, agent_code) },
        state,
        operations,
        params,
        // Все версии записей банка: лимит за период — по истории (расширение со следующего периода).
        clientLimits: { get: (c) => limits.history(c) },
        // Часы стенда (setClock): период лимита клиента и окно дробления — по тем же часам, что резервы и подписи.
        now,
      }),
    },
  });
  const issuer: StandIssuer = {
    participant_code: emulator.participant_code,
    trustedKey: emulator.trustedKey,
    async sign(mandateId, opts = {}) {
      // Экран мандата: хэш записи из журнала — тот же, что в Mandate.hash (РП36 п. 3).
      const view = await consent.signingView(mandateId);
      if (!view) return { statusCode: 404, body: { code: "MANDATE_NOT_FOUND" } };
      const record = {
        participant_code: emulator.participant_code,
        kid: emulator.trustedKey.kid,
        mandate_id: mandateId,
        mandate_hash: view.hash,
        decision: opts.decision ?? "SIGN",
        signature_type: opts.signature_type ?? "simple",
        signature_ref: `emu-sig-${mandateId.slice(-6)}`,
        token_consent: opts.token_consent ?? true,
        signed_at: now().toISOString(),
      } as const;
      const { mandate_id: _id, ...body } = { ...record, signature: emulator.signRecord(record) };
      void _id;
      const res = await app.inject({ method: "POST", url: `/participants/v1/mandates/${mandateId}/sign`, payload: body });
      return { statusCode: res.statusCode, body: res.json() };
    },
    async revoke(mandateId) {
      const view = await consent.signingView(mandateId);
      if (!view) return { statusCode: 404, body: { code: "MANDATE_NOT_FOUND" } };
      const record = {
        participant_code: emulator.participant_code,
        kid: emulator.trustedKey.kid,
        mandate_id: mandateId,
        mandate_hash: view.hash,
        revocation_ref: `emu-rev-${mandateId.slice(-6)}`,
        revoked_at: now().toISOString(),
      };
      const { mandate_id: _id, ...body } = { ...record, signature: emulator.signRevocation(record) };
      void _id;
      const res = await app.inject({ method: "POST", url: `/participants/v1/mandates/${mandateId}/revoke`, payload: body });
      return { statusCode: res.statusCode, body: res.json() };
    },
    async setLimits(principalRef, clientLimits, version) {
      const record = {
        participant_code: emulator.participant_code,
        kid: emulator.trustedKey.kid,
        principal_ref: principalRef,
        version,
        limits: clientLimits as LimitsRecord["limits"],
        issued_at: now().toISOString(),
      };
      const { principal_ref: _ref, ...body } = { ...record, signature: emulator.signLimits(record) };
      void _ref;
      const res = await app.inject({ method: "PUT", url: `/participants/v1/principals/${encodeURIComponent(principalRef)}/limits`, payload: body });
      return { statusCode: res.statusCode, body: res.json() };
    },
    signRequest: (method, path, query, at) => emulator.signRequest(method, path, query, at),
    async getLimits(principalRef) {
      const path = `/participants/v1/principals/${encodeURIComponent(principalRef)}/limits`;
      const res = await app.inject({ method: "GET", url: path, headers: emulator.signRequest("GET", path, "", now()) });
      return { statusCode: res.statusCode, body: res.json() };
    },
    async revokeAll(principalRef, revocationRef) {
      const record = {
        participant_code: emulator.participant_code,
        kid: emulator.trustedKey.kid,
        principal_ref: principalRef,
        revocation_ref: revocationRef,
        revoked_at: now().toISOString(),
      };
      const { principal_ref: _ref, ...body } = { ...record, signature: emulator.signPrincipalRevocation(record) };
      void _ref;
      const res = await app.inject({ method: "POST", url: `/participants/v1/principals/${encodeURIComponent(principalRef)}/revoke-all`, payload: body });
      return { statusCode: res.statusCode, body: res.json() };
    },
  };
  return {
    params,
    registry,
    keys,
    app,
    dns,
    agentReceiver,
    async deliverEvents() {
      let total = 0;
      for (let n = await deliverer.runOnce(); n > 0; n = await deliverer.runOnce()) total += n;
      return total;
    },
    delivery: (id) => consentStore.delivery(id),
    notifyParticipants: () => notifier.runOnce(),
    issuer,
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
