import Fastify, { type FastifyInstance } from "fastify";

// Среды — SPEC §8, ARCHITECTURE «Среды». dev работает в памяти, без PostgreSQL.
export const ENVIRONMENTS = ["dev", "sandbox"] as const;
export type PlatformEnv = (typeof ENVIRONMENTS)[number];

export function parseEnv(value: string | undefined): PlatformEnv {
  const env = value ?? "dev";
  if (!(ENVIRONMENTS as readonly string[]).includes(env)) {
    throw new Error(`Неизвестная среда PLATFORM_ENV=${env}; допустимы: ${ENVIRONMENTS.join(", ")}`);
  }
  return env as PlatformEnv;
}

export interface ServerOptions {
  env: PlatformEnv;
  logger?: boolean;
}

export function buildServer(opts: ServerOptions): FastifyInstance {
  const app = Fastify({ logger: opts.logger ?? false });

  // Живость процесса; к базе не обращается.
  app.get("/health", async () => ({ status: "ok", env: opts.env }));

  return app;
}
