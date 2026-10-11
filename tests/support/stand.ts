// Стенд для сценариев и контрактных тестов: реестр, ключи, проверка ПАО и сервер на стендовых параметрах.
// Параметры — из config/params.stand.json, как в песочнице; часы — подставляемые.
import type { FastifyInstance } from "fastify";
import { PaoRequestVerifier } from "../../src/pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { buildServer } from "../../src/server.js";
import { loadParams, type Params } from "../../src/shared/config.js";

export interface Stand {
  readonly params: Params;
  readonly store: InMemoryAgentRegistryStore;
  readonly registry: AgentRegistry;
  readonly keys: AgentKeys;
  readonly verifier: PaoRequestVerifier;
  readonly app: FastifyInstance;
  setClock(d: Date | undefined): void;
}

export function stand(): Stand {
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
  const app = buildServer({ env: "sandbox", pao: { verifier, keys } });
  return { params, store, registry, keys, verifier, app, setClock: (d) => (clock = d) };
}
