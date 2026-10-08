import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// Проверка каталога сценариев: JSON — источник истины, SCENARIOS.md должен совпадать по кодам.
const catalog = JSON.parse(readFileSync("tests/scenarios/scenarios.json", "utf8"));
const md = readFileSync("docs/core/SCENARIOS.md", "utf8");

describe("каталог сценариев приёмки", () => {
  const ids: string[] = catalog.scenarios.map((s: { id: string }) => s.id);

  it("содержит 28 сценариев с уникальными кодами", () => {
    expect(ids.length).toBe(28);
    expect(new Set(ids).size).toBe(28);
  });

  it("каждый сценарий описан полностью", () => {
    for (const s of catalog.scenarios) {
      for (const f of ["id", "type", "stage", "components", "title", "setup", "action", "expected", "norms", "requirements"]) {
        expect(s[f], `${s.id}.${f}`).toBeTruthy();
      }
      expect(["positive", "negative"]).toContain(s.type);
    }
  });

  it("SCENARIOS.md совпадает с JSON по составу кодов", () => {
    const mdIds = [...md.matchAll(/^\| (ПС\d\d) \|/gmu)].map((m) => m[1]);
    expect(mdIds).toEqual(ids);
  });

  it("коды отказа в сценариях — из перечня контракта", () => {
    const yaml = readFileSync("docs/core/agent-protocol.yaml", "utf8") + readFileSync("docs/core/processing-interface.yaml", "utf8");
    for (const s of catalog.scenarios) for (const c of s.codes) expect(yaml).toContain(c);
  });
});
