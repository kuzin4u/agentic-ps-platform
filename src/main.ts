import { buildServer, parseEnv } from "./server.js";
import { PaoRequestVerifier } from "./pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "./registry/index.js";
import { loadParams } from "./shared/config.js";

const env = parseEnv(process.env.PLATFORM_ENV);
// Неверные стендовые параметры — отказ запуска (fail-closed).
const params = loadParams();
const port = Number(process.env.PORT ?? 8080);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`Недопустимый PORT=${process.env.PORT}`);
}
const host = process.env.HOST ?? "127.0.0.1";

// Реестр в памяти до PostgreSQL (PS-06); допуск операторов по HTTP — после их аутентификации (SEC-1, расхождение №9).
const store = new InMemoryAgentRegistryStore();
const registry = new AgentRegistry(store, { keys: params });
const keys = new AgentKeys(store, { keys: params });
const verifier = new PaoRequestVerifier(
  { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
  { skewSec: params.signature_skew_sec },
);

const app = buildServer({ env, logger: true, pao: { verifier, keys, params } });
app.log.info({ params }, "стендовые параметры загружены");

try {
  await app.listen({ port, host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
