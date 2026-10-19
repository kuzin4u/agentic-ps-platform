// Самопроверка при старте (РП42 п. 4, К17 п. 8): ready: false или замечание к отчёту — порт не открывается, код выхода 1;
// warn готовность не снимает. startPlatform возвращает решение, process.exit — только в src/main.ts (проверяется процессом).
import { execFile, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { checkSelfCheckReport, type SelfCheckReport } from "@kuzin4u/agentic-core/diag";
import { describe, expect, it, vi } from "vitest";
import {
  diagRegistryProblems,
  paoSpecMatches,
  platformVersion,
  runSelfCheck,
  startPlatform,
  type StartupCheck,
  type StartupCode,
} from "../../src/shared/selfcheck.js";
import { PAO_SPEC_SHA256, PAO_SPEC_VERSION, PLATFORM_DIAG } from "../../src/shared/index.js";

const NOW = new Date("2026-10-19T10:00:00.000Z");
const ok = (check: string): StartupCheck => ({ check, fail: "STARTUP_PARAMS_INVALID", run: () => "ok" });
const boom = (check: string, fail: StartupCode): StartupCheck => ({
  check,
  fail,
  run: () => {
    throw new Error("причина для журнала");
  },
});

async function launch(checks: StartupCheck[]) {
  const listen = vi.fn(async () => {});
  const log = vi.fn();
  const res = await startPlatform(checks, { version: "0.7.0", log, listen, now: NOW });
  return { ...res, listen, log };
}

describe("startPlatform: решение о запуске (РП42 п. 4)", () => {
  it("все проверки ok — отчёт готов, порт открывается, код 0", async () => {
    const r = await launch([ok("params"), ok("proxies")]);
    expect(r.exitCode).toBe(0);
    expect(r.listen).toHaveBeenCalledOnce();
    expect(r.decision.report).toEqual({
      component: "platform",
      version: "0.7.0",
      checked_at: "2026-10-19T10:00:00.000Z",
      ready: true,
      checks: [
        { check: "params", status: "ok" },
        { check: "proxies", status: "ok" },
      ],
    });
    expect(checkSelfCheckReport(r.decision.report, PLATFORM_DIAG)).toEqual([]);
    expect(r.log).toHaveBeenCalledWith("info", { selfcheck: r.decision.report }, expect.any(String));
  });

  it("fail — порт не открывается, код 1; причина — в журнал отдельным полем, в отчёте только код", async () => {
    const r = await launch([ok("params"), boom("db.migrations", "STARTUP_DB_MIGRATIONS"), ok("participants")]);
    expect(r.exitCode).toBe(1);
    expect(r.listen).not.toHaveBeenCalled();
    expect(r.decision.report.ready).toBe(false);
    expect(r.decision.report.checks).toContainEqual({ check: "db.migrations", status: "fail", code: "STARTUP_DB_MIGRATIONS" });
    // Остальные проверки выполняются: отчёт показывает всё, что не готово, а не только первое.
    expect(r.decision.report.checks).toContainEqual({ check: "participants", status: "ok" });
    expect(JSON.stringify(r.decision.report)).not.toContain("причина для журнала");
    expect(r.decision.failures).toEqual([{ check: "db.migrations", code: "STARTUP_DB_MIGRATIONS", cause: "причина для журнала" }]);
    expect(r.log).toHaveBeenCalledWith(
      "error",
      { selfcheck: r.decision.report, problems: [], failures: r.decision.failures },
      expect.any(String),
    );
  });

  it("warn STARTUP_DB_MEMORY готовность не снимает — порт открывается, код 0", async () => {
    const r = await launch([ok("params"), { check: "db.storage", fail: "STARTUP_DB_REQUIRED", run: () => ({ warn: "STARTUP_DB_MEMORY" }) }]);
    expect(r.decision.report.ready).toBe(true);
    expect(r.decision.report.checks).toContainEqual({ check: "db.storage", status: "warn", code: "STARTUP_DB_MEMORY" });
    expect(r.exitCode).toBe(0);
    expect(r.listen).toHaveBeenCalledOnce();
  });

  it("замечание checkSelfCheckReport — тоже отказ запуска, даже при ready: true", async () => {
    // Код не из PLATFORM_DIAG (SELFCHECK_CODE_UNKNOWN) и повтор имени проверки (SELFCHECK_DUPLICATE).
    const unknown = await launch([ok("params"), { check: "db.storage", fail: "STARTUP_DB_REQUIRED", run: () => ({ warn: "NOT_A_CODE" as StartupCode }) }]);
    expect(unknown.decision.report.ready).toBe(true);
    expect(unknown.decision.problems.map((p) => p.code)).toEqual(["SELFCHECK_CODE_UNKNOWN"]);
    expect(unknown.exitCode).toBe(1);
    expect(unknown.listen).not.toHaveBeenCalled();

    const dup = await launch([ok("params"), ok("params")]);
    expect(dup.decision.problems.map((p) => p.code)).toEqual(["SELFCHECK_DUPLICATE"]);
    expect(dup.exitCode).toBe(1);
    expect(dup.listen).not.toHaveBeenCalled();
  });

  it("пустой список проверок — замечание SELFCHECK_EMPTY, отказ запуска", async () => {
    const r = await launch([]);
    expect(r.decision.problems.map((p) => p.code)).toEqual(["SELFCHECK_EMPTY"]);
    expect(r.exitCode).toBe(1);
  });

  it("skip — в отчёт не попадает (зависимая проверка после отказа)", async () => {
    const d = await runSelfCheck([boom("db.storage", "STARTUP_DB_REQUIRED"), { check: "db.migrations", fail: "STARTUP_DB_MIGRATIONS", run: () => "skip" }], {
      version: "0.7.0",
      now: NOW,
    });
    expect(d.report.checks).toEqual([{ check: "db.storage", status: "fail", code: "STARTUP_DB_REQUIRED" }]);
  });

  it("сбой listen — код 1", async () => {
    const log = vi.fn();
    const r = await startPlatform([ok("params")], { version: "0.7.0", log, listen: () => Promise.reject(new Error("EADDRINUSE")), now: NOW });
    expect(r.exitCode).toBe(1);
    expect(log).toHaveBeenLastCalledWith("error", { cause: "EADDRINUSE" }, expect.any(String));
  });
});

describe("проверки pao.spec, diag.registry и версия", () => {
  it("pao.spec: копия ПАО ядра равна Платформе; иная версия или sha-256 — несовпадение", () => {
    expect(paoSpecMatches()).toBe(true);
    expect(paoSpecMatches({ version: PAO_SPEC_VERSION, sha256: "0".repeat(64) })).toBe(false);
    expect(paoSpecMatches({ version: "1.3.0", sha256: PAO_SPEC_SHA256 })).toBe(false);
  });

  it("diag.registry: замечаний по трём реестрам нет", () => {
    expect(diagRegistryProblems()).toEqual([]);
  });

  it("версия отчёта — из package.json", () => {
    expect(platformVersion()).toBe((JSON.parse(readFileSync("package.json", "utf8")) as { version: string }).version);
  });
});

// Процесс src/main.ts через tsx: настоящий код выхода и настоящий порт.
const MAIN = ["--import", import.meta.resolve("tsx"), "src/main.ts"];
const baseEnv = (extra: Record<string, string>): NodeJS.ProcessEnv => {
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: process.env.HOME, ...extra };
  return env;
};
const reportFrom = (out: string): SelfCheckReport => {
  const line = out.split("\n").find((l) => l.includes('"selfcheck"'));
  if (!line) throw new Error(`нет записи самопроверки в выводе: ${out}`);
  return (JSON.parse(line) as { selfcheck: SelfCheckReport }).selfcheck;
};

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => (typeof addr === "object" && addr ? resolve(addr.port) : reject(new Error("нет порта"))));
    });
  });
}

describe("src/main.ts: отказ запуска процессом (РП42 п. 4)", () => {
  it("sandbox без DATABASE_URL — код выхода 1, db.storage fail STARTUP_DB_REQUIRED, миграции не выполняются", async () => {
    const port = await freePort();
    const { code, stderr } = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      execFile(process.execPath, MAIN, { env: baseEnv({ PLATFORM_ENV: "sandbox", PORT: String(port) }), timeout: 20_000 }, (err, _out, stderr) =>
        resolve({ code: err ? ((err as { code?: number }).code ?? null) : 0, stderr }),
      );
    });
    expect(code).toBe(1);
    const report = reportFrom(stderr);
    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual({ check: "db.storage", status: "fail", code: "STARTUP_DB_REQUIRED" });
    expect(report.checks.map((c) => c.check)).not.toContain("db.migrations");
    expect(checkSelfCheckReport(report, PLATFORM_DIAG)).toEqual([]);
  }, 30_000);

  it("неизвестная среда — params fail, код выхода 1", async () => {
    const { code, stderr } = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      execFile(process.execPath, MAIN, { env: baseEnv({ PLATFORM_ENV: "prod" }), timeout: 20_000 }, (err, _out, stderr) =>
        resolve({ code: err ? ((err as { code?: number }).code ?? null) : 0, stderr }),
      );
    });
    expect(code).toBe(1);
    expect(reportFrom(stderr).checks).toContainEqual({ check: "params", status: "fail", code: "STARTUP_PARAMS_INVALID" });
  }, 30_000);

  it("dev без базы — warn STARTUP_DB_MEMORY, готов, порт открыт (/health 200)", async () => {
    const port = await freePort();
    const child = spawn(process.execPath, MAIN, { env: baseEnv({ PLATFORM_ENV: "dev", PORT: String(port) }) });
    try {
      let out = "";
      const report = await new Promise<SelfCheckReport>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`нет отчёта: ${out}`)), 20_000);
        child.stdout.on("data", (b: Buffer) => {
          out += b.toString();
          if (out.includes('"selfcheck"')) {
            clearTimeout(timer);
            resolve(reportFrom(out));
          }
        });
        child.once("exit", (c) => reject(new Error(`процесс завершился с кодом ${c}: ${out}`)));
      });
      expect(report.ready).toBe(true);
      expect(report.checks).toContainEqual({ check: "db.storage", status: "warn", code: "STARTUP_DB_MEMORY" });
      // listen после записи отчёта: ждём, пока порт откроется.
      let res: Response | undefined;
      for (let i = 0; i < 100 && !res; i++) {
        res = await fetch(`http://127.0.0.1:${port}/health`).catch(async () => {
          await new Promise((r) => setTimeout(r, 100));
          return undefined;
        });
      }
      expect(res?.status).toBe(200);
    } finally {
      child.kill("SIGTERM");
    }
  }, 30_000);
});
