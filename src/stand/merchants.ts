// Эмуляторы продавцов и эквайрера для тестов агента (РП22 п. 8, AG-09): витрины проверяют подпись агента
// по каталогу ключей реестра стенда (та же функция, что отдаст HTTP-адрес PS-30). ОПКЦ — заглушка до PS-11.
// Значений merchant_jwks_max_age_sec и merchant_jwks_refetch_min_sec ещё нет (PS-30): по умолчанию стенд
// читает каталог при каждом обращении — отзыв ключа виден витрине сразу.
import type { FastifyInstance } from "fastify";
import { Acquirer, OpkcStub } from "../env/acquirer/index.js";
import {
  MerchantAgentVerifier,
  buildMerchantsServer,
  type PackageMetadata,
  type ReconciliationPort,
} from "../env/merchants/index.js";
import type { Stand } from "./index.js";

export interface MerchantsStandOptions {
  /** false — эквайрер без поддержки aoi (РП22 п. 6). По умолчанию true. */
  readonly aoiSupport?: boolean;
  readonly jwksMaxAgeMs?: number;
  readonly jwksRefetchMinMs?: number;
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
  readonly verifier: MerchantAgentVerifier;
  listen(): Promise<string>;
  close(): Promise<void>;
}

export function createMerchants(stand: Stand, opts: MerchantsStandOptions = {}): MerchantsStand {
  const opkc = new OpkcStub(opts.decide);
  const acquirer = new Acquirer({ acquirer_id: "ACQ-01", aoiSupport: opts.aoiSupport ?? true, opkc, now: stand.now });
  const submitted: PackageMetadata[] = [];
  const reconciliation: ReconciliationPort = { submit: async (m) => void submitted.push(m) };
  const verifier = new MerchantAgentVerifier(() => stand.keys.jwks(), {
    maxAgeMs: opts.jwksMaxAgeMs ?? 0,
    refetchMinMs: opts.jwksRefetchMinMs ?? 0,
    skewSec: stand.params.signature_skew_sec,
    now: stand.now,
  });
  const app = buildMerchantsServer({ verifier, acquirer, reconciliation });
  return {
    app,
    acquirer,
    opkc,
    reconciliation: submitted,
    verifier,
    async listen() {
      await app.listen({ host: "127.0.0.1", port: 0 });
      const addr = app.server.address();
      if (!addr || typeof addr === "string") throw new Error("нет адреса сервера витрин");
      return `http://127.0.0.1:${addr.port}`;
    },
    close: () => app.close(),
  };
}
