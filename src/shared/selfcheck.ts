// Самопроверка при старте (РП42 п. 4, К17 п. 8): отчёт «готов / не готов» с кодами PLATFORM_DIAG до приёма трафика.
// ready: false или замечание checkSelfCheckReport — порт не открывается, код выхода 1 (A3 п. 4.5, инвариант 3).
// Решение возвращает startPlatform; process.exit — только в src/main.ts.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  buildSelfCheckReport,
  checkDiagRegistry,
  checkSelfCheckReport,
  type DiagProblem,
  type SelfCheckItem,
  type SelfCheckProblem,
  type SelfCheckReport,
} from "@kuzin4u/agentic-core/diag";
import { PAO_SPEC_SHA256 as CORE_PAO_SPEC_SHA256, PAO_VERSION as CORE_PAO_VERSION } from "@kuzin4u/agentic-core/pao";
import { DECISION_REASON } from "./canonical.generated.js";
import { PAO_DIAG, PI_DIAG, PLATFORM_DIAG, PLATFORM_DIAG_CODES, type STARTUP_CODES } from "./diag.js";
import { PAO_ERROR_CODES, PAO_SPEC_SHA256, PAO_SPEC_VERSION } from "./pao-errors.generated.js";

export type StartupCode = (typeof STARTUP_CODES)[number];

/** Итог проверки: `ok`, предупреждение с кодом или `skip` — проверка не выполнима, потому что не прошла та, от которой она зависит. */
export type StartupOutcome = "ok" | "skip" | { readonly warn: StartupCode };

export interface StartupCheck {
  /** Имя проверки в отчёте (`db.migrations`). */
  readonly check: string;
  /** Код при исключении из `run`. */
  readonly fail: StartupCode;
  readonly run: () => StartupOutcome | Promise<StartupOutcome>;
}

/**
 * Отказ проверки — в журнал процесса отдельным полем, не в отчёт (РП42 п. 4). Только имя проверки и класс ошибки:
 * текст исключения и значения параметров (строка подключения с паролем) в журнал не попадают (РП42 п. 12, условие владельца).
 */
export interface StartupFailure {
  readonly check: string;
  readonly code: StartupCode;
  /** Класс ошибки (`Error`, `TypeError`, `AggregateError`); не Error — `typeof` значения. */
  readonly error: string;
}

export interface StartupDecision {
  readonly report: SelfCheckReport;
  /** Замечания checkSelfCheckReport по PLATFORM_DIAG; непустые — тоже отказ запуска. */
  readonly problems: readonly SelfCheckProblem[];
  readonly failures: readonly StartupFailure[];
  /** Трафик принимается: `ready` и нет замечаний к отчёту. */
  readonly start: boolean;
}

const errorClass = (err: unknown): string => (err instanceof Error ? err.constructor.name || "Error" : typeof err);

/** Проверки по порядку; исключение — `fail` с кодом проверки, `skip` в отчёт не попадает. */
export async function runSelfCheck(
  checks: readonly StartupCheck[],
  opts: { readonly version: string; readonly now?: Date },
): Promise<StartupDecision> {
  const items: SelfCheckItem[] = [];
  const failures: StartupFailure[] = [];
  for (const c of checks) {
    let outcome: StartupOutcome;
    try {
      outcome = await c.run();
    } catch (err) {
      items.push({ check: c.check, status: "fail", code: c.fail });
      failures.push({ check: c.check, code: c.fail, error: errorClass(err) });
      continue;
    }
    if (outcome === "skip") continue;
    items.push(outcome === "ok" ? { check: c.check, status: "ok" } : { check: c.check, status: "warn", code: outcome.warn });
  }
  const report = buildSelfCheckReport("platform", opts.version, items, opts.now);
  const problems = checkSelfCheckReport(report, PLATFORM_DIAG);
  return { report, problems, failures, start: report.ready && problems.length === 0 };
}

export type StartupLog = (level: "info" | "error", fields: Record<string, unknown>, msg: string) => void;

/**
 * Запуск Платформы: самопроверка, запись отчёта одной записью журнала, затем `listen` — только при `start`.
 * Возвращает код выхода: 1 — не готов, замечание к отчёту или сбой `listen`; 0 — порт открыт.
 */
export async function startPlatform(
  checks: readonly StartupCheck[],
  opts: { readonly version: string; readonly log: StartupLog; readonly listen: () => Promise<void>; readonly now?: Date },
): Promise<{ readonly exitCode: 0 | 1; readonly decision: StartupDecision }> {
  const decision = await runSelfCheck(checks, opts);
  const { report, problems, failures } = decision;
  if (!decision.start) {
    opts.log("error", { selfcheck: report, problems, failures }, "самопроверка: не готов — трафик не принимается (РП42)");
    return { exitCode: 1, decision };
  }
  opts.log("info", { selfcheck: report }, "самопроверка: готов (РП42)");
  try {
    await opts.listen();
  } catch (err) {
    opts.log("error", { error: errorClass(err) }, "запуск: порт не открыт");
    return { exitCode: 1, decision };
  }
  return { exitCode: 0, decision };
}

/** Проверка `pao.spec`: копия ПАО ядра — та же, что у Платформы (версия и sha-256). */
export function paoSpecMatches(core = { version: CORE_PAO_VERSION, sha256: CORE_PAO_SPEC_SHA256 }): boolean {
  return core.version === PAO_SPEC_VERSION && core.sha256 === PAO_SPEC_SHA256;
}

/** Проверка `diag.registry`: замечания checkDiagRegistry по трём реестрам (РП42 п. 3). */
export function diagRegistryProblems(): DiagProblem[] {
  return [
    ...checkDiagRegistry(DECISION_REASON, PI_DIAG),
    ...checkDiagRegistry(PLATFORM_DIAG_CODES, PLATFORM_DIAG),
    ...checkDiagRegistry(PAO_ERROR_CODES, PAO_DIAG),
  ];
}

/** Версия пакета Платформы для отчёта. */
export function platformVersion(): string {
  const pkg = JSON.parse(readFileSync(fileURLToPath(new URL("../../package.json", import.meta.url)), "utf8")) as { version?: unknown };
  if (typeof pkg.version !== "string" || pkg.version === "") throw new Error("package.json без версии");
  return pkg.version;
}
