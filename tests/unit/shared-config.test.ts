import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadParams, parseParams, ParamsError } from "../../src/shared/config.js";

const stand = (): Record<string, unknown> => JSON.parse(readFileSync("config/params.stand.json", "utf8"));

describe("стендовые параметры", () => {
  it("стендовый файл загружается полностью и заморожен", () => {
    const p = loadParams("config/params.stand.json");
    const keys = Object.keys(stand()).filter((k) => k !== "_comment");
    expect(Object.keys(p).sort()).toEqual(keys.sort());
    expect(p.adp_availability_target).toBe(99.95);
    expect(Object.isFrozen(p)).toBe(true);
  });

  it("каждый ключ PARAMS.md есть в схеме загрузчика", () => {
    const doc = readFileSync("docs/core/PARAMS.md", "utf8");
    const p = loadParams("config/params.stand.json");
    for (const k of Object.keys(p)) {
      const base = k.replace(/_(kop|days)$/, "_*");
      expect(doc.includes(`\`${k}\``) || doc.includes(`\`${base}\``), k).toBe(true);
    }
  });

  it("нет ключа — отказ, значения по умолчанию нет", () => {
    const raw = stand();
    delete raw.adp_timeout_ms;
    expect(() => parseParams(raw)).toThrow(/adp_timeout_ms: нет ключа/);
  });

  it("лишний ключ — отказ", () => {
    expect(() => parseParams({ ...stand(), adp_p95_ms: 10 })).toThrow(/adp_p95_ms: неизвестный ключ/);
  });

  it.each([
    ["adp_p99_ms", "50"],
    ["adp_p99_ms", -1],
    ["event_retry_max", 1.5],
    ["restore_budget_on_refund", "false"],
    ["aoi_rollout_phase", 4],
    ["issuer_mode_default", "SOMETHING"],
    ["adp_availability_target", 99.95],
    ["adp_availability_target", "101%"],
    ["split_min_ops", 1],
  ])("неверное значение %s = %j — отказ", (k, v) => {
    expect(() => parseParams({ ...stand(), [k]: v })).toThrow(ParamsError);
  });

  it("таймаут ADP меньше p99 — отказ", () => {
    expect(() => parseParams({ ...stand(), adp_timeout_ms: 10 })).toThrow(/adp_timeout_ms меньше adp_p99_ms/);
  });

  it("испорченный файл — отказ запуска", () => {
    const dir = mkdtempSync(join(tmpdir(), "params-"));
    const path = join(dir, "bad.json");
    writeFileSync(path, "{ не json");
    expect(() => loadParams(path)).toThrow(ParamsError);
    expect(() => loadParams(join(dir, "missing.json"))).toThrow(ParamsError);
  });
});
