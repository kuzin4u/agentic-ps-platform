import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import {
  PAO_ERRORS,
  PAO_RETRY_VALUES,
  PAO_SPEC_VERSION,
  paoError,
  UnknownCodeError,
} from "../../src/shared/index.js";
import { CORE_PAO_ERRORS, CORE_PAO_VERSION, ERROR_CODES_MATCH_CORE } from "../../src/shared/pao.js";

const pao = parse(readFileSync("docs/core/agent-protocol.yaml", "utf8"), { maxAliasCount: -1 });

describe("таблица ошибок ПАО (x-pao-errors, РП16)", () => {
  it("совпадает с agent-protocol.yaml Платформы", () => {
    const fromSpec = pao["x-pao-errors"].errors.map((e: Record<string, unknown>) => ({
      code: e.code,
      http: e.http,
      retry: e.retry,
      description: e.description,
    }));
    expect(PAO_ERRORS).toEqual(fromSpec);
    expect(PAO_SPEC_VERSION).toBe(pao.info.version);
  });

  it("retry — только из перечня Error.retry", () => {
    expect([...PAO_RETRY_VALUES]).toEqual(pao.components.schemas.Error.properties.retry.enum);
    for (const e of PAO_ERRORS) expect(PAO_RETRY_VALUES).toContain(e.retry);
  });

  it("таблица AGENT-PROTOCOL.md §6 не расходится с YAML", () => {
    const doc = readFileSync("docs/core/AGENT-PROTOCOL.md", "utf8");
    for (const e of PAO_ERRORS) {
      expect(doc, e.code).toMatch(new RegExp(`\\| ${e.code} \\| ${e.http} \\| [^|]+ \\| ${e.retry} \\|`));
    }
  });

  it("неизвестный код ошибки — исключение", () => {
    expect(paoError("RATE_LIMITED")).toMatchObject({ http: 429, retry: "same_key" });
    expect(() => paoError("TEAPOT")).toThrow(UnknownCodeError);
  });

  it("набор кодов совпадает с типами agentic-core", () => {
    expect(ERROR_CODES_MATCH_CORE).toBe(true);
  });
});

// Платформа может выпустить ПАО раньше core: тогда сверка ждёт выпуска agentic-core.
// Core новее Платформы быть не может — его спецификация берётся из Платформы.
const CORE_BEHIND = "платформа впереди core, ждём выпуск agentic-core";
const cmpVersion = (a: string, b: string): number => {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
};
const platformAhead = cmpVersion(PAO_SPEC_VERSION, CORE_PAO_VERSION) > 0;

describe("сверка с agentic-core", () => {
  it("версия ПАО core не новее спецификации Платформы", () => {
    expect(cmpVersion(PAO_SPEC_VERSION, CORE_PAO_VERSION)).toBeGreaterThanOrEqual(0);
  });

  it("версия ПАО совпадает с agentic-core", (ctx) => {
    if (platformAhead) ctx.skip(CORE_BEHIND);
    expect(CORE_PAO_VERSION).toBe(PAO_SPEC_VERSION);
  });

  it("HTTP и retry каждого кода совпадают с agentic-core", (ctx) => {
    if (platformAhead) ctx.skip(CORE_BEHIND);
    for (const e of PAO_ERRORS) {
      expect(CORE_PAO_ERRORS[e.code], e.code).toMatchObject({ http: e.http, retry: e.retry });
    }
  });
});

describe("генерация src/shared", () => {
  it("сгенерированные файлы соответствуют спецификациям", () => {
    expect(() => execFileSync("node", ["scripts/gen-shared.mjs", "--check"], { stdio: "pipe" })).not.toThrow();
  });
});
