// Эмуляторы продавцов и эквайрера для тестов агента (РП22 п. 8, AG-09): витрины проверяют подпись агента
// по каталогу ключей реестра стенда (та же функция, что отдаёт GET /.well-known/agent-keys). ОПКЦ — заглушка до PS-11.
// Срок кэша и окно перечитывания — merchant_jwks_max_age_sec и merchant_jwks_refetch_min_sec (РП56 п. 3; на стенде
// 1 и 1 с): отзыв ключа виден витрине не позже чем через секунду; явные значения — для тестов окна.
import type { FastifyInstance } from "fastify";
import { Acquirer, OpkcStub } from "../env/acquirer/index.js";
import {
  MerchantAgentVerifier,
  buildMerchantsServer,
  type PackageMetadata,
  type ReconciliationPort,
  type ShopListFailure,
} from "../env/merchants/index.js";
import type { Stand } from "./index.js";

export interface MerchantsStandOptions {
  /** false — эквайрер без поддержки aoi (РП22 п. 6). По умолчанию true. */
  readonly aoiSupport?: boolean;
  readonly jwksMaxAgeMs?: number;
  readonly jwksRefetchMinMs?: number;
  /** Лимит обращений с адреса в минуту; по умолчанию — `merchant_rate_limit_per_min` стенда. */
  readonly rateLimitPerMin?: number;
  /** Решение заглушки ОПКЦ; по умолчанию одобрение. */
  readonly decide?: ConstructorParameters<typeof OpkcStub>[0];
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
  listen(): Promise<string>;
  close(): Promise<void>;
}

export function createMerchants(stand: Stand, opts: MerchantsStandOptions = {}): MerchantsStand {
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
  let shopListFailure: ShopListFailure | null = null;
  const app = buildMerchantsServer({
    verifier,
    acquirer,
    reconciliation,
    rateLimitPerMin: opts.rateLimitPerMin ?? stand.params.merchant_rate_limit_per_min,
    shopListFailure: () => shopListFailure,
  });
  return {
    app,
    acquirer,
    opkc,
    reconciliation: submitted,
    reconciliationReplies: replies,
    verifier,
    failShopList: (failure) => void (shopListFailure = failure),
    async listen() {
      await app.listen({ host: "127.0.0.1", port: 0 });
      const addr = app.server.address();
      if (!addr || typeof addr === "string") throw new Error("нет адреса сервера витрин");
      return `http://127.0.0.1:${addr.port}`;
    },
    close: () => app.close(),
  };
}
