// Дымовой тест рабочей сборки на PostgreSQL (решение владельца 27.10, PS-05в ч. 2б-2 К3а; РП64 п. 7): src/main.ts —
// отдельным процессом с DATABASE_URL на пустой схеме. Самопроверка применяет миграции (sql/120 — реестр агентов),
// /health отвечает, а реестр читается из базы: агент, допущенный в эту схему другим пулом, виден в каталоге ключей
// процесса. Процесс — без оболочки, остановка по номеру. В CI (РП30 п. 7); локально без базы — пропуск.
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AgentRegistry, PgAgentRegistryStore } from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { DATABASE_URL } from "../support/pg.js";

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      s.close(() => (typeof addr === "object" && addr ? resolve(addr.port) : reject(new Error("порт не получен"))));
    });
  });

const stop = (child: ChildProcess): Promise<number | null> =>
  new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve(child.exitCode);
    child.once("exit", (code) => resolve(code));
    child.kill("SIGTERM");
  });

describe.skipIf(!DATABASE_URL)("рабочая сборка src/main.ts на PostgreSQL (dev, DATABASE_URL; РП64 п. 7)", () => {
  const schema = `t_${process.pid}_${Date.now()}_mainpg`;
  let admin: pg.Pool;
  let pool: pg.Pool;
  let url: string;
  let child: ChildProcess | undefined;

  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Пустая схема: миграции применяет сам main.ts. search_path — параметром строки подключения (и пул, и миграции).
    const u = new URL(DATABASE_URL as string);
    u.searchParams.set("options", `-c search_path=${schema}`);
    url = u.toString();
    pool = new pg.Pool({ connectionString: url, max: 2 });
  });
  afterAll(async () => {
    if (child) await stop(child);
    await pool?.end();
    await admin?.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin?.end();
  });

  it("миграции применены самопроверкой, /health — 200, реестр агентов — из базы (агент другого пула в каталоге ключей)", async () => {
    const port = await freePort();
    const env: NodeJS.ProcessEnv = { ...process.env, PLATFORM_ENV: "dev", PORT: String(port), HOST: "127.0.0.1", DATABASE_URL: url };
    for (const k of ["PAO_TRUSTED_PROXIES", "PARTICIPANT_KEYS_PATH"]) delete env[k];
    const proc = spawn(process.execPath, ["--import", "tsx", "src/main.ts"], { env, stdio: ["ignore", "pipe", "pipe"] });
    child = proc;
    let out = "";
    proc.stdout?.on("data", (d: Buffer) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d: Buffer) => (out += d.toString("utf8")));
    const base = `http://127.0.0.1:${port}`;

    let ready = false;
    for (let i = 0; i < 150 && !ready; i++) {
      expect(proc.exitCode, out).toBeNull();
      ready = await fetch(`${base}/health`).then((r) => r.status === 200, () => false);
      if (!ready) await new Promise((r) => setTimeout(r, 200));
    }
    expect(ready, out).toBe(true);

    // Миграции — в этой схеме, включая реестр агентов (sql/120).
    const applied = (await pool.query<{ name: string }>("SELECT name FROM core_migrations")).rows.map((r) => r.name);
    expect(applied).toContain("120_agent_registry.sql");
    expect(out).not.toContain("DATABASE_URL не задан");

    // Агент допущен в эту схему другим пулом — процесс видит его ключ: реестр читается из базы, не из своей памяти.
    const code = `nspk:agent:mainpg-${Date.now().toString(36)}:v1`;
    const decision = await new AgentRegistry(new PgAgentRegistryStore(pool), { keys: loadParams() }).admit(buyerApplication(code, newAgentSide()), {
      contour: "sandbox",
      operator: "op-main-pg",
    });
    expect(decision.admitted).toBe(true);
    const jwks = await fetch(`${base}/.well-known/agent-keys`);
    expect(jwks.status).toBe(200);
    expect(((await jwks.json()) as { keys: { agent_code: string }[] }).keys.map((k) => k.agent_code)).toContain(code);

    expect(await stop(proc)).toBe(0);
    child = undefined;
  }, 90_000);
});
