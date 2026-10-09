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
import { CORE_PAO_VERSION, ERROR_CODES_MATCH_CORE } from "../../src/shared/pao.js";

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
    expect(CORE_PAO_VERSION).toMatch(/^1\./);
  });

  it("сгенерированные файлы соответствуют спецификациям", () => {
    expect(() => execFileSync("node", ["scripts/gen-shared.mjs", "--check"], { stdio: "pipe" })).not.toThrow();
  });
});
