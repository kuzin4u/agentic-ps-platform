import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  loadParams,
  parseParams,
  ParamsError,
} from "../../src/shared/config.js";

const stand = (): Record<string, unknown> =>
  JSON.parse(readFileSync("config/params.stand.json", "utf8"));

describe("стендовые параметры", () => {
  it("стендовый файл загружается полностью и заморожен", () => {
    const p = loadParams("config/params.stand.json");
    const keys = Object.keys(stand()).filter((k) => k !== "_comment");
    expect(Object.keys(p).sort()).toEqual(keys.sort());
    expect(p.adp_availability_target).toBe(99.95);
    expect(Object.isFrozen(p)).toBe(true);
  });

  it("ключи PARAMS.md и загрузчика совпадают в обе стороны", () => {
    const doc = readFileSync("docs/core/PARAMS.md", "utf8");
    const end = doc.indexOf("## Журнал");
    expect(end).toBeGreaterThan(0);
    const table = doc.slice(0, end);
    const loader = Object.keys(loadParams("config/params.stand.json"));
    const documented = new Set<string>();
    for (const line of table.split("\n")) {
      const cell = /^\| (`[^|]+`) \|/.exec(line)?.[1];
      if (!cell) continue;
      for (const m of cell.matchAll(/`([a-z0-9_*]+)`/g)) {
        const key = m[1] as string;
        if (!key.endsWith("_*")) {
          documented.add(key);
          continue;
        }
        // Шаблон раскрывается только в суффиксы единиц, которые стоят в колонке «Стенд»: ₽ → _kop, дней → _days.
        const expanded = ["_kop", "_days"].map((u) => key.slice(0, -2) + u);
        for (const k of expanded) expect(loader, k).toContain(k);
        for (const k of expanded) documented.add(k);
      }
    }
    expect([...documented].sort()).toEqual([...loader].sort());
  });

  it.each(["constructor", "__proto__", "toString", "hasOwnProperty"])(
    "ключ прототипа %s не считается параметром",
    (k) => {
      const raw = JSON.parse(`{${JSON.stringify(k)}: 1}`) as Record<
        string,
        unknown
      >;
      Object.assign(raw, stand());
      expect(() => parseParams(raw)).toThrow(
        new RegExp(`${k}: неизвестный ключ`),
      );
    },
  );

  it("отсутствующий ключ не берётся из прототипа", () => {
    const raw = Object.create({ adp_timeout_ms: 150 }) as Record<
      string,
      unknown
    >;
    const rest = stand();
    delete rest.adp_timeout_ms;
    Object.assign(raw, rest);
    expect(() => parseParams(raw)).toThrow(/adp_timeout_ms: нет ключа/);
  });

  it("нет ключа — отказ, значения по умолчанию нет", () => {
    const raw = stand();
    delete raw.adp_timeout_ms;
    expect(() => parseParams(raw)).toThrow(/adp_timeout_ms: нет ключа/);
  });

  it("лишний ключ — отказ", () => {
    expect(() => parseParams({ ...stand(), adp_p95_ms: 10 })).toThrow(
      /adp_p95_ms: неизвестный ключ/,
    );
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

  it.each([
    ["adp_timeout_ms", 10, /adp_timeout_ms не больше adp_p99_ms/],
    ["adp_timeout_ms", 50, /adp_timeout_ms не больше adp_p99_ms/],
    ["bypass_overhead_ms", 50, /bypass_overhead_ms не меньше adp_p99_ms/],
    ["bypass_overhead_ms", 60, /bypass_overhead_ms не меньше adp_p99_ms/],
    ["key_overlap_days", 90, /key_overlap_days не меньше key_ttl_days/],
    ["protocol_overlap_days", 0, /protocol_overlap_days: ожидается целое 1/],
    ["event_retry_max", 0, /event_retry_max: ожидается целое 1/],
  ])("перекрёстное правило и граница: %s = %j — отказ (РП20)", (k, v, msg) => {
    expect(() => parseParams({ ...stand(), [k]: v })).toThrow(msg);
  });

  it("границы PARAMS.md совпадают с загрузчиком (РП20)", () => {
    const doc = readFileSync("docs/core/PARAMS.md", "utf8");
    const from = doc.indexOf("## Границы");
    const to = doc.indexOf("## Журнал");
    expect(from).toBeGreaterThan(0);
    expect(to).toBeGreaterThan(from);
    const section = doc.slice(from, to);
    const keysOf = (label: string): string[] => {
      const row = section.split("\n").find((l) => l.startsWith(`| ${label}`));
      expect(row, label).toBeDefined();
      return [
        ...(row as string).split("|")[1]!.matchAll(/`([a-z0-9_]+)`/g),
      ].map((m) => m[1] as string);
    };
    const min1 = keysOf("Целые ≥ 1:");
    const min0 = keysOf("Целые ≥ 0:");
    // Каждое целое без особой границы — ровно в одной из строк.
    const special = new Set(["split_min_ops", "aoi_rollout_phase"]);
    const ints = Object.entries(stand())
      .filter(([k, v]) => Number.isInteger(v) && !special.has(k))
      .map(([k]) => k);
    expect([...min1, ...min0].sort()).toEqual(ints.sort());
    for (const k of min1)
      expect(() => parseParams({ ...stand(), [k]: 0 }), k).toThrow(
        new RegExp(`${k}: ожидается целое 1`),
      );
    for (const k of min0) {
      expect(() => parseParams({ ...stand(), [k]: -1 }), k).toThrow(
        new RegExp(`${k}: ожидается целое 0`),
      );
      expect(() => parseParams({ ...stand(), [k]: 0 }), k).not.toThrow();
    }
    for (const rule of [
      "`bypass_overhead_ms` < `adp_p99_ms`",
      "`adp_timeout_ms` > `adp_p99_ms`",
      "`key_overlap_days` < `key_ttl_days`",
    ]) {
      expect(section, rule).toContain(rule);
    }
  });

  it("PARAMS_PATH описан в PARAMS.md", () => {
    expect(readFileSync("docs/core/PARAMS.md", "utf8")).toContain(
      "`PARAMS_PATH`",
    );
  });

  it("испорченный файл — отказ запуска", () => {
    const dir = mkdtempSync(join(tmpdir(), "params-"));
    const path = join(dir, "bad.json");
    writeFileSync(path, "{ не json");
    expect(() => loadParams(path)).toThrow(ParamsError);
    expect(() => loadParams(join(dir, "missing.json"))).toThrow(ParamsError);
  });
});
