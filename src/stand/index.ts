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
import { createUpkEmulator } from "../env/upk/index.js";
import { UpkCodes } from "../env/upk/codes.js";
import { createUpkPage, type UpkPageSettings } from "../env/upk/page.js";
import { createTokenServiceEmulator, type TokenServiceEmulator } from "../env/tsp/index.js";
import { merchantDirectory } from "../env/merchants/shops.js";
import { Credentials, MemoryCredentialStore } from "../credentials/index.js";
import { MemoryConfirmationStore, totalsHash, type ConfirmationStore } from "../confirm/index.js";
import { createIssuerWebhookReceiver, STAND_ISSUER_NOTIFY_URL, type IssuerWebhookReceiver } from "../env/issuer/webhook.js";
import { MemoryOutcomeStore, OperationOutcomeCollector, type CollectorResult } from "../fulfilment/outcomes.js";
import { MemoryFulfilmentStore } from "../fulfilment/records.js";
import { MemoryOpLock } from "../fulfilment/oplock.js";
import { MemoryRefundStore } from "../fulfilment/refunds.js";
import { MemoryReversalStore } from "../fulfilment/reversals.js";
import { EventDeliverer, type DeliveryRow } from "../pao/delivery.js";
import { pushAllowed, type PaoEventType } from "../pao/events.js";
import { MemoryLimitsStore, type LimitsRecord } from "../participants/limits.js";
import {
  MemoryParticipantNotificationStore,
  ParticipantNotifier,
  type NoticeDeliveryRow,
  type NotifierResult,
} from "../participants/notifications.js";
import { WebhookDeliverer } from "../participants/webhook.js";
import { TrustedParticipants, type TrustedParticipantKey } from "../participants/trusted.js";
import { ParticipantRequestVerifier } from "../participants/verify.js";
import { paoIdempotency } from "../pao/idempotency.js";
import { PaoRequestVerifier } from "../pao/verify.js";
import {
  AgentKeys,
  AgentRegistry,
  AgentStatusService,
  InMemoryAgentRegistryStore,
  type AdmissionDecision,
  type AgentRecord,
} from "../registry/index.js";
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
  /**
   * Лента уведомлений клиента через банк (РП46 (б) п. 3, ПИ-8 `GET /participants/v1/notifications`) с подписью запроса
   * банка; after — notification_id последнего прочитанного. Уведомления по решениям ADP — после stand.notifyParticipants().
   */
  getNotifications(after?: string): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /**
   * Решение человека по запросу подтверждения в приложении банка (РП50 п. 4–5, ПИ-8 `POST /participants/v1/confirmations/{id}`):
   * банк показывает итог запроса, подписывает запись с totals_hash этого итога. Ответ шлюза участников — 200
   * `{confirmation_id, status, confirmation_ref?}` или `{code}`; неизвестный запрос — 404 без обращения. opts — для
   * тестов отказов: другое время решения или другой хэш итога.
   */
  confirm(confirmationId: string, opts?: IssuerConfirmOptions): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /**
   * Одноразовый код страницы УПК (РП51 п. 15, «Дополнения» п. 8): человек получил его в банке — вне ПАО, агенту
   * недоступен. Привязан к запросу, истекает вместе с ним; новый код заменяет прежний. Запроса нет — undefined.
   */
  upkCode(confirmationId: string): Promise<string | undefined>;
}

/** Страница УПК стенда (РП51 п. 15): адрес link — upk_page_base_url + /c/{id}; здесь — путь /c/{id}. */
export interface StandUpk {
  readonly app: FastifyInstance;
  /** Запуск на 127.0.0.1 и свободном порту; базовый адрес страницы. */
  listen(): Promise<string>;
}

export interface StandOptions {
  /** Язык и бренд страницы УПК (правило совместимости 3); по умолчанию — ru и бренд стенда. */
  readonly upk?: UpkPageSettings;
}

export interface IssuerConfirmOptions {
  readonly decision?: "APPROVE" | "REJECT";
  readonly decided_at?: string;
  readonly totals_hash?: string;
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
  /**
   * Проход сборщика итогов операций по часам стенда (РП52 п. 1 (а)): итог и событие operation.declined по решённым отказам
   * ADP вне пути авторизации. Таймера на стенде нет — тест вызывает проход сам.
   */
  collectOperationOutcomes(): Promise<CollectorResult>;
  /**
   * Проход срока резервов П3 по часам стенда (РП41 п. 6): освобождение истёкших удержаний; число освобождённых. Таймера на
   * стенде нет — тест вызывает проход сам (позднее представление, РП53 п. 6).
   */
  expireReservations(): Promise<number>;
  /**
   * Проход вебхука-сигнала банку стенда по часам стенда (РП46 (б) п. 3): все готовые попытки до пустой очереди; число
   * попыток. Повтор — по nextAttemptDelayMs ядра, тест двигает часы. Приёмник — issuerWebhook.
   */
  deliverParticipantNotifications(): Promise<number>;
  /** Строка попытки вебхука по уведомлению — для тестов. */
  notificationDelivery(notification_id: string): Promise<NoticeDeliveryRow | undefined>;
  /** Приёмник вебхука банка стенда: ответы по очереди, полученные и обработанные сигналы. */
  readonly issuerWebhook: IssuerWebhookReceiver;
  /** Приложение банка: подпись и отзыв мандата клиентом (РП12, РП36, РП38). */
  readonly issuer: StandIssuer;
  /** Страница УПК (РП51 п. 15–16): оператор УПК — участник ПИ-8 с ролью UPK, ключ в памяти. */
  readonly upk: StandUpk;
  /**
   * Запросы подтверждения П6 только для чтения (РП50): найти запрос по заказу до GET /pao/v1/confirmations/{id} (PS-19
   * ч. 2). Записи нет — решение только через приложение банка (issuer.confirm), инвариант 7.
   */
  readonly confirmations: Pick<ConfirmationStore, "get" | "byKey">;
  /** Эмулятор токен-сервиса (ПИ-4, РП47): выпущенные токены и проверка криптограммы — для тестов. */
  readonly tsp: Pick<TokenServiceEmulator, "issued" | "verify">;
  /** Подставляемые часы реестра, ключей и проверки подписи; undefined — системные. */
  setClock(d: Date | undefined): void;
  /** Текущее время стенда — те же часы, что у реестра и эмуляторов. */
  now(): Date;
  /** Допуск по заявлению (РП21, РП23) в контуре sandbox; оператор — от вызывающего (только стенд, №9). */
  admit(application: unknown, operator: string): AdmissionDecision;
  /**
   * Действие оператора Системы (РП54 п. 1, ПС25): приостановление с основанием A2 п. 7.1 и событие agent.suspended.
   * Повтор с тем же основанием дописывает недостающее событие; HTTP оператора — PS-32.
   */
  suspendAgent(agent_code: string, ground: string): Promise<AgentRecord>;
  /** Снятие приостановления и событие agent.reinstated (РП54 п. 1, 10). */
  reinstateAgent(agent_code: string): Promise<AgentRecord>;
  /** Запуск на 127.0.0.1 и свободном порту; возвращает базовый адрес для клиента ПАО. */
  listen(): Promise<string>;
  close(): Promise<void>;
}

// Хранилище и проверка подписи наружу не отдаются: через хранилище тест мог бы записать агента в обход допуска
// (инвариант 5). Параметры — только config/params.stand.json Платформы или PARAMS_PATH (РП25 п. 4).
export function createStand(opts: StandOptions = {}): Stand {
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
  // Адрес вебхука банка стенда — в записи доверенного участника (РП46 доп. п. 9 (о4)).
  // Оператор УПК стенда (РП51 п. 12): роль UPK, только решения по подтверждению; боевой UPK — отказ запуска.
  const upkEmulator = createUpkEmulator();
  const trusted = new TrustedParticipants([{ ...emulator.trustedKey, notify_url: STAND_ISSUER_NOTIFY_URL }, upkEmulator.trustedKey], { stand: true });
  // Push по событию — только ACTIVE-агенту, подписанному на тип, на момент записи (РП40 п. 5–6).
  // Outbox участника стенда — в памяти; журнал согласий пишет в него client.mandate_exhausted и client.revoked_all.
  const operations = new MemoryOperationStore();
  const notifications = new MemoryParticipantNotificationStore(operations);
  const consentStore = new MemoryConsentStore({ notifications });
  const pushFor = (code: string, type: PaoEventType): boolean =>
    pushAllowed(registry.get(code)?.status, type) && (registry.subscription(code)?.events.includes(type) ?? false);
  // Приостановление и снятие — одно действие оператора со событием в ленте стенда (РП54 п. 1–2).
  const agentStatus = new AgentStatusService(registry, { events: consentStore, pushFor });
  const consent: ConsentJournal = new ConsentJournal(consentStore, {
    now,
    revocationOrder: () => trusted.revocationOrder(),
    pushFor,
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
  const notifier = new ParticipantNotifier(notifications, {
    horizonSec: params.participant_notify_horizon_sec,
    now: () => now().getTime(),
  });
  // Итоги операций (РП52): записи ADP стенда — память, события — в ленту журнала стенда, push — по тому же правилу.
  const outcomeStore = new MemoryOutcomeStore(operations, consentStore);
  // Записи об исполнении (РП53): та же лента журнала стенда.
  const fulfilmentStore = new MemoryFulfilmentStore(consentStore);
  // Реверсалы и истечение авторизации (РП55 п. 1): записи в памяти, событий нет до ПАО 1.5.0.
  const reversalStore = new MemoryReversalStore();
  // Возвраты (РП55 п. 3): записи и operation.refunded — в ленту журнала стенда; бюджет не восстанавливается.
  const refundStore = new MemoryRefundStore(consentStore);
  const outcomes = new OperationOutcomeCollector(outcomeStore, {
    horizonSec: params.operation_outcome_horizon_sec,
    maxDelaySec: params.operation_outcome_max_delay_sec,
    pushFor,
    now: () => now().getTime(),
  });
  // Вебхук-сигнал банку стенда: проверка адреса та же, что в рабочем сервере, подменены разрешение имени и транспорт.
  const issuerWebhook = createIssuerWebhookReceiver();
  const webhook = new WebhookDeliverer({
    store: notifications,
    notifyUrl: (code) => trusted.notifyUrl(code),
    resolveHost: dns.resolve,
    transport: issuerWebhook.transport,
    params,
    now: () => now().getTime(),
    stand: true,
  });
  // Агентские реквизиты (П5, РП47): токен-сервис — эмулятор с ключом в памяти, funding_ref — от банка стенда.
  const tsp = createTokenServiceEmulator();
  const credentialStore = new MemoryCredentialStore();
  // Подтверждение человеком (П6, РП50): запросы ADP и решения банка стенда — одно хранилище в памяти; переходы пишут
  // события confirmation.* в ленту журнала стенда (РП51 п. 1–3), push — по тому же правилу, что у мандатов.
  const confirmationStore = new MemoryConfirmationStore({ events: consentStore, pushFor });
  const credentials = new Credentials({
    mandates: { get: (id, agent_code) => consent.credentialMandate(id, agent_code) },
    store: credentialStore,
    tsp,
    funding: emulator,
    // Справочник продавцов (РП49 (д)): витрины эмулятора, на продавца — MCC витрины.
    merchants: merchantDirectory(),
    params,
    now,
  });
  const app = buildServer({
    env: "dev",
    notifier,
    outcomes,
    pao: {
      verifier,
      keys,
      idempotency,
      params,
      consent,
      subscriptions,
      credentials,
      // Запрос подтверждения агенту (РП51 п. 8–10): то же хранилище П6, часы стенда, link — на страницу УПК.
      confirmations: { store: confirmationStore, now, upk_page_base_url: params.upk_page_base_url },
      // Операция агенту (РП52 п. 10): записи ADP и итоги П8 — те же хранилища в памяти, что у ADP и ПИ-3.
      operations: { operations, outcomes: outcomeStore, fulfilments: fulfilmentStore, reversals: reversalStore, refunds: refundStore, list: operations },
      resolveHost: dns.resolve,
      stand: true,
    },
    participants: {
      trusted,
      consent,
      params,
      state,
      limits,
      now,
      requests: new ParticipantRequestVerifier(trusted, { skewSec: params.signature_skew_sec, now }),
      notifications,
      // Решение человека по подтверждению (РП50 п. 4–5): то же хранилище П6, что у ADP; допуск часов — окно подписи.
      confirmations: { store: confirmationStore, skewSec: params.signature_skew_sec },
    },
    // API для продавцов (РП56): каталог ключей агентов и статус агента — реестр стенда, контур sandbox.
    merchants: { registry, keys, contour: "sandbox", params },
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
        // Домен токена, криптограмма и погашение — то же хранилище П5, что выдаёт реквизиты (РП47 п. 6–8).
        credentials: credentialStore,
        // Запрос на CONFIRMATION_REQUIRED, проверка и погашение confirmation_ref (РП50 п. 1–3, 7–10).
        confirmations: { store: confirmationStore, order_hold_sec: params.order_hold_sec },
        // Часы стенда (setClock): период лимита клиента и окно дробления — по тем же часам, что резервы и подписи.
        now,
      }),
      // ПИ-3 стенда (РП52 п. 1 (б), РП53): ответ эмитента — итог и событие в ленту журнала стенда, освобождение — П3 стенда;
      // клиринг — закрепление П3 стенда, запись об исполнении и operation.settled; реверсал и истечение авторизации —
      // освобождение П3 стенда и запись (РП55 п. 1); событие без предшественника — 503, за окном — инцидент (п. 5).
      events: {
        operations,
        store: outcomeStore,
        state,
        pushFor,
        now,
        fulfilments: fulfilmentStore,
        reversals: reversalStore,
        refunds: refundStore,
        // Обработчики одной операции — по одному (РП55 «Дополнения КТ1» п. 1).
        lock: new MemoryOpLock(),
        reorder_window_ms: params.event_reorder_window_ms,
      },
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
    async getNotifications(after) {
      const path = "/participants/v1/notifications";
      const query = after === undefined ? "" : `after=${encodeURIComponent(after)}`;
      const url = query === "" ? path : `${path}?${query}`;
      const res = await app.inject({ method: "GET", url, headers: emulator.signRequest("GET", path, query, now()) });
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
    async confirm(confirmationId, opts = {}) {
      // Экран подтверждения: итог запроса — тот, что видит человек; хэш — от него (РП50 п. 4).
      const view = await confirmationStore.get(confirmationId);
      if (!view) return { statusCode: 404, body: { code: "CONFIRMATION_NOT_FOUND" } };
      const record = {
        participant_code: emulator.participant_code,
        kid: emulator.trustedKey.kid,
        confirmation_id: confirmationId,
        decision: opts.decision ?? "APPROVE",
        totals_hash: opts.totals_hash ?? totalsHash(view),
        decided_at: opts.decided_at ?? now().toISOString(),
      } as const;
      const { confirmation_id: _id, ...body } = { ...record, signature: emulator.signConfirmation(record) };
      void _id;
      const res = await app.inject({ method: "POST", url: `/participants/v1/confirmations/${confirmationId}`, payload: body });
      return { statusCode: res.statusCode, body: res.json() };
    },
    async upkCode(confirmationId) {
      const r = await confirmationStore.get(confirmationId);
      return r ? upkCodes.issue(confirmationId, r.expires_at) : undefined;
    },
  };
  // Страница УПК: итог — из записи П6, решение — ПИ-8 того же сервера (как приложение банка), выбор СБП — по параметру.
  const upkCodes = new UpkCodes();
  const upkApp = createUpkPage({
    upk: upkEmulator,
    confirmations: { get: (id) => confirmationStore.get(id) },
    codes: upkCodes,
    async submit(id, body) {
      const res = await app.inject({ method: "POST", url: `/participants/v1/confirmations/${id}`, payload: body });
      return { statusCode: res.statusCode, body: res.json() };
    },
    sbpEnabled: params.upk_sbp_enabled,
    now,
    ...(opts.upk ? { settings: opts.upk } : {}),
  });
  const upk: StandUpk = {
    app: upkApp,
    async listen() {
      await upkApp.listen({ host: "127.0.0.1", port: 0 });
      const addr = upkApp.server.address();
      if (!addr || typeof addr === "string") throw new Error("нет адреса страницы УПК");
      return `http://127.0.0.1:${addr.port}`;
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
    collectOperationOutcomes: () => outcomes.runOnce(),
    expireReservations: async () => (await state.expire()).length,
    async deliverParticipantNotifications() {
      let total = 0;
      for (let n = await webhook.runOnce(); n > 0; n = await webhook.runOnce()) total += n;
      return total;
    },
    notificationDelivery: (id) => notifications.delivery(id),
    issuerWebhook,
    issuer,
    upk,
    confirmations: { get: (id) => confirmationStore.get(id), byKey: (key) => confirmationStore.byKey(key) },
    tsp,
    setClock: (d) => (clock = d),
    now,
    admit: (application, operator) => registry.admit(application, { contour: "sandbox", operator }),
    suspendAgent: (agent_code, ground) => agentStatus.suspend(agent_code, ground),
    reinstateAgent: (agent_code) => agentStatus.reinstate(agent_code),
    async listen() {
      await app.listen({ host: "127.0.0.1", port: 0 });
      const addr = app.server.address();
      if (!addr || typeof addr === "string") throw new Error("нет адреса сервера стенда");
      return `http://127.0.0.1:${addr.port}`;
    },
    async close() {
      await upkApp.close();
      await app.close();
    },
  };
}

export { createMerchants, type MerchantsStand, type MerchantsStandOptions } from "./merchants.js";
