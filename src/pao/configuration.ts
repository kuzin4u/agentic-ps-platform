// П9 Обнаружение ПАО: GET /.well-known/pao-configuration (ПАО §3, §7; РП60 п. 9–14). Без подписи и проверки обращения —
// своей областью, как API продавцов (РП56); грубый лимит по адресу — свой счётчик (РП32, РП60 п. 11).
import type { FastifyInstance, FastifyReply } from "fastify";
import { DEFAULT_KEY_ALGORITHMS } from "../registry/keys.js";
import type { Contour } from "../registry/model.js";
import type { Params } from "../shared/config.js";
import type { Configuration } from "../shared/pao.js";
import { PAO_SPEC_VERSION } from "../shared/pao-errors.generated.js";
import { paoError } from "./errors.js";
import { paoCoarseLimit } from "./routes.js";

export const PAO_CONFIGURATION_PATH = "/.well-known/pao-configuration";

export interface PaoConfigurationDeps {
  /** Контур развёртывания: algorithms — что принимает его реестр (РП23 п. 2, РП60 п. 9). */
  readonly contour: Contour;
  readonly params: Pick<Params, "pao_rate_limit_per_30s">;
}

type Algorithm = NonNullable<Configuration["algorithms"]>[number];

/**
 * Строго по схеме Configuration ПАО 1.4.0, без новых полей (РП60 п. 9–10): versions — полная версия контракта, а не v1;
 * platform_keys — пусто до SEC-1 (подпись ответов и событий — с 1.5.0); endpoints не отдаётся — базового публичного адреса
 * в конфигурации Платформы нет. Стендовые параметры для агента — в ПАО 1.5.0.
 */
export function paoConfiguration(contour: Contour): Configuration {
  return {
    versions: [PAO_SPEC_VERSION],
    sunset: {},
    platform_keys: [],
    algorithms: DEFAULT_KEY_ALGORITHMS[contour].map((a) => a.alg as Algorithm),
  };
}

export async function paoConfigurationRoutes(app: FastifyInstance, deps: PaoConfigurationDeps): Promise<void> {
  await paoCoarseLimit(app, deps.params.pao_rate_limit_per_30s);
  const body = paoConfiguration(deps.contour);
  // no-cache: агент перечитывает конфигурацию при неизвестном kid ключа Платформы (РП26 п. 5) — кэш прокси не должен
  // отдавать старую; срок — вместе с platform_keys_refetch_min_sec в ПАО 1.5.0 (РП60 п. 11).
  app.get(PAO_CONFIGURATION_PATH, async (_req, reply) => reply.header("cache-control", "no-cache").send(body));
}

/**
 * Режим «только BYPASS» (РП43 п. 8; РП60 п. 12): 503 UPSTREAM_UNAVAILABLE по ПАО §6 с Retry-After, а не 404 Fastify —
 * агент отличает «Платформа недоступна» от «метода нет».
 */
export async function paoConfigurationUnavailable(app: FastifyInstance, retryAfterSec: number): Promise<void> {
  app.get(PAO_CONFIGURATION_PATH, async (_req, reply: FastifyReply) =>
    reply.code(503).header("retry-after", String(retryAfterSec)).send(paoError("UPSTREAM_UNAVAILABLE").body),
  );
}
