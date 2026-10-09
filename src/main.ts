import { buildServer, parseEnv } from "./server.js";
import { loadParams } from "./shared/config.js";

const env = parseEnv(process.env.PLATFORM_ENV);
// Неверные стендовые параметры — отказ запуска (fail-closed).
const params = loadParams();
const port = Number(process.env.PORT ?? 8080);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`Недопустимый PORT=${process.env.PORT}`);
}
const host = process.env.HOST ?? "127.0.0.1";

const app = buildServer({ env, logger: true });
app.log.info({ params }, "стендовые параметры загружены");

try {
  await app.listen({ port, host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
