// Стенд Платформы для тестов агента (РП25): среда dev (в одном процессе внутри теста агента),
// контур ключей sandbox (ed25519, РП23). Песочницей (средой sandbox) не является; приёмку не заменяет.
// Тестовый интерфейс, не публичный контракт: публичный контракт для агентов — только ПАО (инвариант 10).
// Оператор при допуске — от вызывающего: обход расхождения №9 допустим только здесь. Рабочий сервер
// (src/main.ts и его граф импортов) этот модуль не импортирует — проверяет tests/unit/stand-boundary.test.ts.
import type { FastifyInstance } from "fastify";
import { ConsentJournal, MemoryConsentStore } from "../consent/index.js";
import type { MandateDecisionPayload } from "../consent/model.js";
import { createIssuerEmulator } from "../env/issuer/index.js";
import { TrustedParticipants, type TrustedParticipantKey } from "../participants/trusted.js";
import { paoIdempotency } from "../pao/idempotency.js";
import { PaoRequestVerifier } from "../pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore, type AdmissionDecision } from "../registry/index.js";
import { buildServer } from "../server.js";
import { loadParams, type Params } from "../shared/config.js";

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
}

export interface Stand {
  readonly params: Params;
  readonly registry: AgentRegistry;
  readonly keys: AgentKeys;
  readonly app: FastifyInstance;
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
  const consent = new ConsentJournal(new MemoryConsentStore(), { now, revocationOrder: () => trusted.revocationOrder() });
  const app = buildServer({
    env: "dev",
    pao: { verifier, keys, idempotency, params, consent },
    participants: { trusted, consent, params },
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
  };
  return {
    params,
    registry,
    keys,
    app,
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
