// РП57 п. 4: путь чтения знака готовности агентом — код с v0.24.0, в agent-protocol.yaml — с ПАО 1.5.0 (как № 41).
// Тест фиксирует отсутствие: покраснеет при объявлении пути — тогда заменить проверкой схемы ответа.
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { PAO_SPEC_SHA256 } from "../../src/shared/pao-errors.generated.js";

const pao = parse(readFileSync("docs/core/agent-protocol.yaml", "utf8")) as { info: { version: string }; paths: Record<string, unknown> };

describe("ПАО: GET /pao/v1/merchants/{merchant_id}/readiness — до 1.5.0 вне YAML (РП57 п. 4)", () => {
  it("пути нет в agent-protocol.yaml, версия ПАО и PAO_SPEC_SHA256 прежние (копия у агента не меняется)", () => {
    expect(Object.keys(pao.paths).filter((p) => p.includes("/merchants"))).toEqual([]);
    expect(pao.info.version.startsWith("1.4.")).toBe(true);
    expect(PAO_SPEC_SHA256).toBe("48bd339746e83c0468fb8354d6b2d8f0c82020904af549063d3e44b1a51ad9da");
  });
});
