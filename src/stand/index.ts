// Стенд Платформы для тестов агента (РП25): среда dev (в одном процессе внутри теста агента),
// контур ключей sandbox (ed25519, РП23). Песочницей (средой sandbox) не является; приёмку не заменяет.
// Тестовый интерфейс, не публичный контракт: публичный контракт для агентов — только ПАО (инвариант 10).
// Оператор при допуске — от вызывающего: обход расхождения №9 допустим только здесь. Рабочий сервер
// (src/main.ts и его граф импортов) этот модуль не импортирует — проверяет tests/unit/stand-boundary.test.ts.
import { randomUUID } from "node:crypto";
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
import { merchantDirectory, SHOPS } from "../env/merchants/shops.js";
import { createAcquirerParticipant } from "../env/acquirer/participant.js";
import { MemoryReadinessStore, type ReadinessStore, type ReadinessSuspendReason } from "../participants/readiness.js";
import { MemoryPaymentMetadataStore } from "../participants/payments.js";
import { Credentials, MemoryCredentialStore } from "../credentials/index.js";
import { MemoryConfirmationStore, totalsHash, type ConfirmationStore } from "../confirm/index.js";
import { createIssuerWebhookReceiver, STAND_ISSUER_NOTIFY_URL, type IssuerWebhookReceiver } from "../env/issuer/webhook.js";
import { MemoryOutcomeStore, OperationOutcomeCollector, type CollectorResult } from "../fulfilment/outcomes.js";
import { MemoryFulfilmentStore } from "../fulfilment/records.js";
import { MemoryOpLock } from "../fulfilment/oplock.js";
import { MemoryRefundStore } from "../fulfilment/refunds.js";
import { MemoryReversalStore } from "../fulfilment/reversals.js";
import { EventDeliverer, type DeliveryRow } from "../pao/delivery.js";
import { pushForRegistry } from "../pao/events.js";
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
  SandboxCa,
  type AdmissionDecision,
  type AgentRecord,
} from "../registry/index.js";
import { buildServer } from "../server.js";
import { loadParams, type Params } from "../shared/config.js";
import { holdLedger, StateService } from "../state/index.js";
import { attachCallJournal, type StandCall } from "./calls.js";
import { createStandDns, type StandDns } from "./dns.js";

export type { StandCall } from "./calls.js";

/** Выданная стендом пара реквизита — только для доказательного теста утечки (инвариант 1). */
export interface IssuedCredential {
  readonly token_ref: string;
  readonly cryptogram: string;
}

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

/**
 * Эквайрер стенда — участник ПИ-8 с ролью ACQUIRER (РП57 п. 1, 7): перечень продавцов — merchant_id всех витрин эмулятора;
 * при старте стенда подаёт знак ACTIVE витринам с readiness_mark тем же POST ПИ-8. Чтения знака продавцом и агентом,
 * методы этого объекта, действия оператора и listen() ждут этой подачи; её сбой — 503 у чтений и отказ listen().
 * Подача идёт через app.inject внутри createStand: приложение стенда загружено сразу, маршруты в stand.app после
 * создания не добавляются (передача агенту, ревью КТ1 № 4).
 */
export interface StandAcquirer {
  readonly participant_code: string;
  readonly trustedKey: TrustedParticipantKey;
  /**
   * Запись знака эквайрера (ПИ-8 `POST /participants/v1/merchants/{id}/readiness`): ответ — 200 `{merchant_id, status,
   * since}` или `{code}`. opts — для тестов: своя ссылка записи и время issued_at.
   */
  submitReadiness(
    merchant_id: string,
    status: "ACTIVE" | "WITHDRAWN",
    opts?: { readonly readiness_ref?: string; readonly issued_at?: string },
  ): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /** Статус знака своего продавца с причиной (ПИ-8 `GET …/readiness`) с подписью запроса эквайрера. */
  getReadiness(merchant_id: string): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /**
   * Метаданные пакета за продавца (ПИ-8 `POST /participants/v1/merchants/{id}/payments`, РП57 п. 5): ответ — 200 сверка
   * `{credential_ref, result, aoi_checked, op_ref?, fields?, reason?}` или `{code}`. aoi — если эквайрер его получил.
   */
  submitPaymentMetadata(
    merchant_id: string,
    m: {
      readonly credential_ref: string;
      readonly order_ref: string;
      readonly aoi?: { readonly agent_code: string; readonly mandate_id: string };
      readonly metadata_ref?: string;
      readonly submitted_at?: string;
    },
  ): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /** Сверка по реквизиту (ПИ-8 `GET …/payments/{credential_ref}`) с подписью запроса эквайрера. */
  getReconciliation(merchant_id: string, credential_ref: string): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /** Статус агента для эквайрера (ПИ-8 `GET /participants/v1/agents/{code}/status`, РП57 п. 6) с подписью запроса. */
  getAgentStatus(agent_code: string): Promise<{ readonly statusCode: number; readonly body: unknown }>;
  /** Заголовки подписанного запроса эквайрера без тела (RFC 9421) — для тестов отказов. */
  signRequest(method: string, path: string, query: string, at: Date): Record<string, string>;
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
  /**
   * Корневой сертификат УЦ стенда, DER в base64 (РП65 п. 1): им подписан сертификат из решения о допуске, если в заявлении
   * был csr. Стенд — без mTLS (РП27 п. 5): сертификат на стенде не проверяется; УЦ — в памяти, у каждого стенда свой.
   */
  readonly caCertificate: string;
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
  /**
   * Журнал обращений к приложению стенда (РП25 дополнение STAND-69): метод, путь без строки запроса, статус, code при
   * 4xx / 5xx, kid, x-nonce, Idempotency-Key, source network / inject. Тел нет. Копия — по порядку завершения обращений.
   */
  calls(): readonly StandCall[];
  /**
   * Выданные пары token_ref и cryptogram по порядку выпуска, без повторов — только в стенде, для теста утечки реквизита
   * (инвариант 1): в журнал обращений они не пишутся, хранилище П5 криптограмму не хранит.
   */
  issuedCredentials(): readonly IssuedCredential[];
  /** Подставляемые часы реестра, ключей и проверки подписи; undefined — системные. */
  setClock(d: Date | undefined): void;
  /** Текущее время стенда — те же часы, что у реестра и эмуляторов. */
  now(): Date;
  /** Допуск по заявлению (РП21, РП23) в контуре sandbox; оператор — от вызывающего (только стенд, №9). */
  admit(application: unknown, operator: string): Promise<AdmissionDecision>;
  /**
   * Действие оператора Системы (РП54 п. 1, ПС25): приостановление с основанием A2 п. 7.1 и событие agent.suspended.
   * Повтор с тем же основанием дописывает недостающее событие; HTTP оператора — PS-32.
   */
  suspendAgent(agent_code: string, ground: string): Promise<AgentRecord>;
  /** Снятие приостановления и событие agent.reinstated (РП54 п. 1, 10). */
  reinstateAgent(agent_code: string): Promise<AgentRecord>;
  /** Эквайрер стенда — участник ПИ-8 (РП57 п. 1): знак готовности витрин. */
  readonly acquirerParticipant: StandAcquirer;
  /**
   * Действие оператора Системы (A5 п. 5.3, РП57 п. 2): приостановление знака готовности с причиной; действует, пока
   * оператор его не снимет, какие бы записи ни присылал эквайрер. HTTP оператора — PS-31.
   */
  suspendReadiness(merchant_id: string, reason: ReadinessSuspendReason): Promise<void>;
  /** Снятие приостановления знака оператором: статус снова — по записям эквайрера. */
  reinstateReadiness(merchant_id: string): Promise<void>;
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
  // УЦ стенда — в памяти, CSR необязателен (РП65 п. 1): агент на стенде CSR не шлёт. Срок УЦ отсчитывается от часов при
  // создании стенда: допуск с CSR при часах раньше этого — исключение УЦ «вне срока».
  const ca = SandboxCa.generate({ now: now(), ttlDays: params.sandbox_ca_ttl_days });
  const registry = new AgentRegistry(store, {
    keys: params,
    now,
    certificates: {
      ca,
      ttlDays: params.agent_cert_ttl_days,
      backdateSec: params.cert_not_before_backdate_sec,
      required: false,
      // Вид причины — только в журнал процесса, оператору — KEY_INVALID (РП65 п. 1). app создаётся ниже; допуск — после.
      onRejected: (reason) => app.log.info({ reason }, "П1: CSR заявления отклонён — KEY_INVALID"),
    },
  });
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
  // Эквайрер стенда (РП57 п. 1, 7): роль ACQUIRER, продавцы — все витрины эмулятора.
  const acquirerEmulator = createAcquirerParticipant(SHOPS.map((s) => s.merchant_id));
  const trusted = new TrustedParticipants(
    [{ ...emulator.trustedKey, notify_url: STAND_ISSUER_NOTIFY_URL }, upkEmulator.trustedKey, acquirerEmulator.trustedKey],
    { stand: true },
  );
  // Знак готовности (РП57 п. 2): записи в памяти. Чтения продавца и агента ждут подачи знаков витрин при старте (ниже);
  // маршруты ПИ-8 эквайрера — нет: подача сама идёт через них.
  const readinessStore = new MemoryReadinessStore();
  let readinessSeeded: Promise<void> = Promise.resolve();
  const seededReadiness: Pick<ReadinessStore, "current"> = {
    current: async (merchant_id) => {
      await readinessSeeded;
      return readinessStore.current(merchant_id);
    },
  };
  // Push по событию — только ACTIVE-агенту, подписанному на тип, на момент записи (РП40 п. 5–6).
  // Outbox участника стенда — в памяти; журнал согласий пишет в него client.mandate_exhausted и client.revoked_all.
  const operations = new MemoryOperationStore();
  const notifications = new MemoryParticipantNotificationStore(operations);
  const consentStore = new MemoryConsentStore({ notifications });
  const pushFor = pushForRegistry(registry);
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
  // Выданные пары (STAND-69): обёртка токен-сервиса для П5 — криптограмма детерминирована, повтор и пересчёт дают ту же пару.
  const issuedPairs = new Map<string, IssuedCredential>();
  const recordingTsp: typeof tsp = {
    ...tsp,
    async cryptogram(input) {
      const cryptogram = await tsp.cryptogram(input);
      const key = JSON.stringify([input.token_ref, cryptogram]);
      if (!issuedPairs.has(key)) issuedPairs.set(key, Object.freeze({ token_ref: input.token_ref, cryptogram }));
      return cryptogram;
    },
  };
  const credentialStore = new MemoryCredentialStore();
  // Подтверждение человеком (П6, РП50): запросы ADP и решения банка стенда — одно хранилище в памяти; переходы пишут
  // события confirmation.* в ленту журнала стенда (РП51 п. 1–3), push — по тому же правилу, что у мандатов.
  const confirmationStore = new MemoryConfirmationStore({ events: consentStore, pushFor });
  const credentials = new Credentials({
    mandates: { get: (id, agent_code) => consent.credentialMandate(id, agent_code) },
    store: credentialStore,
    tsp: recordingTsp,
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
      // Знак готовности агенту (РП57 п. 3–4): то же хранилище, что у ПИ-8 и API продавцов.
      readiness: seededReadiness,
      resolveHost: dns.resolve,
      stand: true,
    },
    // Обнаружение ПАО (РП60 п. 13): как в рабочем сервере — та же функция, контур sandbox.
    paoConfiguration: { contour: "sandbox", params },
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
      // Знак готовности (РП57 п. 2): записи эквайрера стенда; допуск часов issued_at — окно подписи.
      readiness: { store: readinessStore, skewSec: params.signature_skew_sec },
      // Метаданные пакета и сверка (РП57 п. 5): записи реквизитов — то же хранилище П5, мандат — журнал, отсечка — реестр.
      payments: {
        store: new MemoryPaymentMetadataStore(),
        reconcile: {
          credentials: credentialStore,
          mandateStatus: async (id, agent_code) => (await consent.adpMandate(id, agent_code))?.status,
          suspendedAt: async (agent_code) => (await registry.get(agent_code))?.suspended_at ?? null,
          now,
        },
        skewSec: params.signature_skew_sec,
      },
      // Статус агента для эквайрера (РП57 п. 6): реестр стенда, контур sandbox.
      agentStatus: { registry, contour: "sandbox" },
    },
    // API для продавцов (РП56, РП57 п. 3): каталог ключей, статус агента — реестр стенда, контур sandbox; знак — записи стенда.
    merchants: { registry, keys, contour: "sandbox", params, readiness: seededReadiness },
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
  // Журнал обращений (STAND-69) — до первого app.inject (подача знаков ниже): хуки регистрируются до загрузки приложения.
  const calls = attachCallJournal(app);
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
  // Подача знака эквайрером — тем же POST ПИ-8; начальная подача стенда вызывает её напрямую, публичный метод — после неё.
  const submitReadiness: StandAcquirer["submitReadiness"] = async (merchant_id, status, opts = {}) => {
    const record = {
      participant_code: acquirerEmulator.participant_code,
      kid: acquirerEmulator.trustedKey.kid,
      merchant_id,
      readiness_ref: opts.readiness_ref ?? `rdy-${randomUUID()}`,
      status,
      issued_at: opts.issued_at ?? now().toISOString(),
    } as const;
    const { merchant_id: _id, ...body } = { ...record, signature: acquirerEmulator.signReadiness(record) };
    void _id;
    const res = await app.inject({ method: "POST", url: `/participants/v1/merchants/${encodeURIComponent(merchant_id)}/readiness`, payload: body });
    return { statusCode: res.statusCode, body: res.json() };
  };
  const acquirerParticipant: StandAcquirer = {
    participant_code: acquirerEmulator.participant_code,
    trustedKey: acquirerEmulator.trustedKey,
    // После начальной подачи (ревью КТ1 № 2): иначе снятие сразу после createStand легло бы раньше начальной ACTIVE.
    async submitReadiness(merchant_id, status, opts) {
      await readinessSeeded;
      return submitReadiness(merchant_id, status, opts);
    },
    async getReadiness(merchant_id) {
      await readinessSeeded;
      const path = `/participants/v1/merchants/${encodeURIComponent(merchant_id)}/readiness`;
      const res = await app.inject({ method: "GET", url: path, headers: acquirerEmulator.signRequest("GET", path, "", now()) });
      return { statusCode: res.statusCode, body: res.json() };
    },
    async submitPaymentMetadata(merchant_id, m) {
      const record = {
        participant_code: acquirerEmulator.participant_code,
        kid: acquirerEmulator.trustedKey.kid,
        merchant_id,
        metadata_ref: m.metadata_ref ?? `meta-${randomUUID()}`,
        credential_ref: m.credential_ref,
        order_ref: m.order_ref,
        ...(m.aoi ? { aoi: { agent_code: m.aoi.agent_code, mandate_id: m.aoi.mandate_id } } : {}),
        submitted_at: m.submitted_at ?? now().toISOString(),
      };
      const { merchant_id: _id, ...body } = { ...record, signature: acquirerEmulator.signPaymentMetadata(record) };
      void _id;
      const res = await app.inject({ method: "POST", url: `/participants/v1/merchants/${encodeURIComponent(merchant_id)}/payments`, payload: body });
      return { statusCode: res.statusCode, body: res.json() };
    },
    async getReconciliation(merchant_id, credential_ref) {
      const path = `/participants/v1/merchants/${encodeURIComponent(merchant_id)}/payments/${encodeURIComponent(credential_ref)}`;
      const res = await app.inject({ method: "GET", url: path, headers: acquirerEmulator.signRequest("GET", path, "", now()) });
      return { statusCode: res.statusCode, body: res.json() };
    },
    async getAgentStatus(agent_code) {
      const path = `/participants/v1/agents/${encodeURIComponent(agent_code)}/status`;
      const res = await app.inject({ method: "GET", url: path, headers: acquirerEmulator.signRequest("GET", path, "", now()) });
      return { statusCode: res.statusCode, body: res.json() };
    },
    signRequest: (method, path, query, at) => acquirerEmulator.signRequest(method, path, query, at),
  };
  // Знаки витрин стенда (РП57 п. 7): эквайрер подаёт ACTIVE витринам с readiness_mark тем же POST ПИ-8; у MKT-77 — NONE.
  // Сбой подачи — чтения знака продавцом и агентом отвечают 503 (fail-closed), а не «знака нет».
  readinessSeeded = (async () => {
    for (const shop of SHOPS.filter((s) => s.readiness_mark)) {
      const r = await submitReadiness(shop.merchant_id, "ACTIVE", { readiness_ref: `seed-${shop.merchant_id}` });
      if (r.statusCode !== 200) throw new Error(`стенд: знак ${shop.merchant_id} не подан — ${r.statusCode} ${JSON.stringify(r.body)}`);
    }
  })();
  readinessSeeded.catch(() => undefined);
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
    calls,
    issuedCredentials: () => [...issuedPairs.values()],
    setClock: (d) => (clock = d),
    now,
    caCertificate: ca.certificateDer.toString("base64"),
    admit: (application, operator) => registry.admit(application, { contour: "sandbox", operator }),
    suspendAgent: (agent_code, ground) => agentStatus.suspend(agent_code, ground),
    reinstateAgent: (agent_code) => agentStatus.reinstate(agent_code),
    acquirerParticipant,
    async suspendReadiness(merchant_id, reason) {
      await readinessSeeded;
      await readinessStore.putOperator({ merchant_id, action: "SUSPENDED", reason, received_at: now().toISOString() });
    },
    async reinstateReadiness(merchant_id) {
      await readinessSeeded;
      await readinessStore.putOperator({ merchant_id, action: "REINSTATED", reason: null, received_at: now().toISOString() });
    },
    async listen() {
      // Сбой начальной подачи знаков роняет запуск, а не всплывает первым 503 (ревью КТ1 № 3).
      await readinessSeeded;
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
