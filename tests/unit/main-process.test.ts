// Рабочая сборка (остаточный риск v0.26.0; РП60 п. 9–13, РП61 п. 3): src/main.ts — отдельным процессом, dev без базы,
// 127.0.0.1, свободный порт. Маршруты отзыва и конфигурации подключены в main.ts, а журнал при logger: true — с шаблоном
// маршрута, без url и значений пути. Процесс запускается без оболочки и останавливается только по своему номеру.
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SandboxCa } from "../../src/registry/ca/ca.js";

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      s.close(() => (typeof addr === "object" && addr ? resolve(addr.port) : reject(new Error("порт не получен"))));
    });
  });

/** Остановка по номеру процесса (SIGTERM — штатная остановка main.ts) и ожидание выхода; код выхода. */
const stop = (child: ChildProcess): Promise<number | null> =>
  new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve(child.exitCode);
    child.once("exit", (code) => resolve(code));
    child.kill("SIGTERM");
  });

describe("рабочая сборка src/main.ts (dev, без базы)", () => {
  let child: ChildProcess | undefined;
  afterEach(async () => {
    if (child) await stop(child);
    child = undefined;
  });

  it("конфигурация — 200, отзыв без подписи — 401 (маршрут есть); журнал — шаблон маршрута без значений пути", async () => {
    const port = await freePort();
    const env: NodeJS.ProcessEnv = { ...process.env, PLATFORM_ENV: "dev", PORT: String(port), HOST: "127.0.0.1" };
    // Без базы и внешних настроек: переменные CI и оболочки не попадают в сборку.
    for (const k of ["DATABASE_URL", "PAO_TRUSTED_PROXIES", "PARTICIPANT_KEYS_PATH"]) delete env[k];
    const proc = spawn(process.execPath, ["--import", "tsx", "src/main.ts"], { env, stdio: ["ignore", "pipe", "pipe"] });
    child = proc;
    let out = "";
    proc.stdout?.on("data", (d: Buffer) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d: Buffer) => (out += d.toString("utf8")));
    const base = `http://127.0.0.1:${port}`;

    // Готовность — по /health; процесс, вышедший раньше (самопроверка не прошла), — провал с журналом.
    let ready = false;
    for (let i = 0; i < 100 && !ready; i++) {
      expect(proc.exitCode, out).toBeNull();
      ready = await fetch(`${base}/health`).then((r) => r.status === 200, () => false);
      if (!ready) await new Promise((r) => setTimeout(r, 200));
    }
    expect(ready, out).toBe(true);

    const conf = await fetch(`${base}/.well-known/pao-configuration`);
    expect(conf.status).toBe(200);
    expect(await conf.json()).toMatchObject({ versions: ["1.4.0"], algorithms: ["ed25519"] });

    const mark = `mark${randomUUID().replaceAll("-", "")}`;
    const revoke = await fetch(`${base}/pao/v1/agent/keys/${mark}/revoke?q=${mark}`, { method: "POST" });
    expect(revoke.status).toBe(401);
    expect(await revoke.json()).toMatchObject({ code: "AGENT_UNKNOWN" });

    expect(await stop(proc)).toBe(0);
    const lines = out
      .split("\n")
      .filter((l) => l.startsWith("{"))
      .map((l) => JSON.parse(l) as Record<string, unknown> & { req?: Record<string, unknown> });
    const incoming = lines.filter((e) => e.msg === "incoming request");
    expect(incoming.map((e) => e.req?.route)).toEqual(
      expect.arrayContaining(["/health", "/.well-known/pao-configuration", "/pao/v1/agent/keys/:kid/revoke"]),
    );
    for (const e of incoming) expect(e.req).not.toHaveProperty("url");
    expect(out).not.toContain(mark);
  }, 60_000);
});

describe("рабочая сборка src/main.ts (sandbox): ключ УЦ — STARTUP_CA_KEY_INVALID (РП66 п. 6)", () => {
  /** Запуск до выхода: отказ самопроверки — код 1 без открытия порта; запись отказа — последняя строка JSON уровня error. */
  const failures = (extra: NodeJS.ProcessEnv) => {
    const env: NodeJS.ProcessEnv = { ...process.env, PLATFORM_ENV: "sandbox", PORT: "1", HOST: "127.0.0.1", ...extra };
    for (const k of ["DATABASE_URL", "PAO_TRUSTED_PROXIES", "PARTICIPANT_KEYS_PATH"]) delete env[k];
    if (extra.PLATFORM_CA_KEY_PATH === undefined) delete env.PLATFORM_CA_KEY_PATH;
    const r = spawnSync(process.execPath, ["--import", "tsx", "src/main.ts"], { env, encoding: "utf8" });
    const out = `${r.stdout}${r.stderr}`;
    const rec = out
      .split("\n")
      .filter((l) => l.startsWith("{"))
      .map((l) => JSON.parse(l) as { level?: string; failures?: Record<string, unknown>[] })
      .find((e) => e.level === "error" && e.failures);
    return { code: r.status, out, failures: rec?.failures ?? [] };
  };

  it("пути нет — отказ запуска, вид причины NO_PATH; файл с правами 0644 — MODE_TOO_OPEN, ключа в журнале нет", () => {
    const none = failures({});
    expect(none.code, none.out).toBe(1);
    expect(none.failures).toContainEqual({ check: "ca.key", code: "STARTUP_CA_KEY_INVALID", error: "CaKeyError", reason: "NO_PATH" });

    const p = join(mkdtempSync(join(tmpdir(), "main-ca-")), "ca.pem");
    const pem = SandboxCa.generate({ now: new Date(), ttlDays: 3650 }).exportPem();
    writeFileSync(p, pem, { mode: 0o644 });
    chmodSync(p, 0o644);
    const open = failures({ PLATFORM_CA_KEY_PATH: p });
    expect(open.code, open.out).toBe(1);
    expect(open.failures).toContainEqual({ check: "ca.key", code: "STARTUP_CA_KEY_INVALID", error: "CaKeyError", reason: "MODE_TOO_OPEN" });
    expect(open.out).not.toContain(["PRIVATE", "KEY"].join(" "));
    expect(open.out).not.toContain(pem.split("\n")[1]);
    expect(open.out).not.toContain(p);
  }, 60_000);

  it("PLATFORM_TLS_HOSTNAMES (РП66 п. 4; № 7): нет или 256.1.1.1 — STARTUP_PARAMS_INVALID; localhost,127.0.0.1 — params проходит", () => {
    const params = { check: "params", code: "STARTUP_PARAMS_INVALID", error: "Error" };
    expect(failures({}).failures).toContainEqual(params);
    expect(failures({ PLATFORM_TLS_HOSTNAMES: "localhost,256.1.1.1" }).failures).toContainEqual(params);
    // Остальные отказы (нет базы и ключа УЦ) — свои; params среди них нет.
    const ok = failures({ PLATFORM_TLS_HOSTNAMES: "localhost,127.0.0.1" });
    expect(ok.code).toBe(1);
    expect(ok.failures.map((f) => f.check)).not.toContain("params");
  }, 60_000);
});
