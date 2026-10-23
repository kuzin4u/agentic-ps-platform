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
      const raw = JSON.parse(`{${JSON.stringify(k)}: 1}`) as Record<string, unknown>;
      Object.assign(raw, stand());
      expect(() => parseParams(raw)).toThrow(new RegExp(`${k}: неизвестный ключ`));
    },
  );

  it("отсутствующий ключ не берётся из прототипа", () => {
    const raw = Object.create({ adp_timeout_ms: 150 }) as Record<string, unknown>;
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

  it("event_subscription_allow_hosts: имена DNS в нижнем регистре, пустой допустим, массив заморожен (РП40 п. 2)", () => {
    expect(parseParams({ ...stand(), event_subscription_allow_hosts: [] }).event_subscription_allow_hosts).toEqual([]);
    const p = parseParams({ ...stand(), event_subscription_allow_hosts: ["agent.example", "a-1.b.example"] });
    expect(p.event_subscription_allow_hosts).toEqual(["agent.example", "a-1.b.example"]);
    expect(Object.isFrozen(p.event_subscription_allow_hosts)).toBe(true);
    for (const v of [
      "agent.example",
      ["Agent.example"],
      ["10.0.0.1"],
      ["[::1]"],
      ["*.example"],
      ["-a.example"],
      ["a..example"],
      ["agent.example:443"],
      [""],
      [1],
      ["a.example", "a.example"],
    ]) {
      expect(() => parseParams({ ...stand(), event_subscription_allow_hosts: v }), JSON.stringify(v)).toThrow(
        /event_subscription_allow_hosts:/,
      );
    }
  });

  it("unavailable_retry_after_sec: 0 и 30 принимаются, 31 — отказ (РП24: не больше maxRetryAfterSec клиента core)", () => {
    for (const v of [0, 30]) expect(parseParams({ ...stand(), unavailable_retry_after_sec: v }).unavailable_retry_after_sec).toBe(v);
    for (const v of [31, -1, 1.5, "1"]) {
      expect(() => parseParams({ ...stand(), unavailable_retry_after_sec: v }), String(v)).toThrow(
        /unavailable_retry_after_sec: ожидается целое 0…30/,
      );
    }
    const doc = readFileSync("docs/core/PARAMS.md", "utf8");
    expect(doc.slice(doc.indexOf("## Границы"), doc.indexOf("## Журнал"))).toContain(
      "| `unavailable_retry_after_sec` — целое 0…30 |",
    );
  });

  it("idempotency_ttl_sec: 60 принимается, 59 — отказ (РП30: не меньше аренды захвата ядра)", () => {
    expect(parseParams({ ...stand(), idempotency_ttl_sec: 60 }).idempotency_ttl_sec).toBe(60);
    expect(() => parseParams({ ...stand(), idempotency_ttl_sec: 59 })).toThrow(/idempotency_ttl_sec: ожидается целое 60/);
    const doc = readFileSync("docs/core/PARAMS.md", "utf8");
    expect(doc.slice(doc.indexOf("## Границы"), doc.indexOf("## Журнал"))).toContain("| `idempotency_ttl_sec` — целое ≥ 60 |");
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
      return [...(row as string).split("|")[1]!.matchAll(/`([a-z0-9_]+)`/g)].map((m) => m[1] as string);
    };
    const min1 = keysOf("Целые ≥ 1:");
    const min0 = keysOf("Целые ≥ 0:");
    // Каждое целое без особой границы — ровно в одной из строк.
    const special = new Set(["split_min_ops", "aoi_rollout_phase", "unavailable_retry_after_sec", "idempotency_ttl_sec"]);
    const ints = Object.entries(stand())
      .filter(([k, v]) => Number.isInteger(v) && !special.has(k))
      .map(([k]) => k);
    expect([...min1, ...min0].sort()).toEqual(ints.sort());
    for (const k of min1)
      expect(() => parseParams({ ...stand(), [k]: 0 }), k).toThrow(new RegExp(`${k}: ожидается целое 1`));
    for (const k of min0) {
      expect(() => parseParams({ ...stand(), [k]: -1 }), k).toThrow(new RegExp(`${k}: ожидается целое 0`));
      expect(() => parseParams({ ...stand(), [k]: 0 }), k).not.toThrow();
    }
    for (const rule of [
      "`bypass_overhead_ms` < `adp_p99_ms`",
      "`adp_timeout_ms` > `adp_p99_ms`",
      "`key_overlap_days` < `key_ttl_days`",
      "`participant_notify_horizon_sec` ≥ 2 × `participant_notify_max_delay_sec`",
      "`operation_outcome_every_ms` < `operation_outcome_max_delay_sec` × 1000",
      "`operation_outcome_horizon_sec` ≥ 2 × `operation_outcome_max_delay_sec`",
      "`operation_reread_interval_sec` — целое ≥ 1, меньше `reservation_ttl_sec`",
      "`restore_budget_on_refund` — булево; `true` — отказ запуска до PS-23",
    ]) {
      expect(section, rule).toContain(rule);
    }
  });

  it("participant_notify_horizon_sec не меньше двух participant_notify_max_delay_sec (РП46 доп. п. 9 (о2))", () => {
    expect(parseParams({ ...stand(), participant_notify_max_delay_sec: 60, participant_notify_horizon_sec: 120 }).participant_notify_horizon_sec).toBe(120);
    expect(() => parseParams({ ...stand(), participant_notify_max_delay_sec: 60, participant_notify_horizon_sec: 119 })).toThrow(
      /participant_notify_horizon_sec меньше двух participant_notify_max_delay_sec/,
    );
  });

  it("сборщик итогов: every_ms < max_delay_sec × 1000, горизонт ≥ 2 × max_delay_sec (РП52 «Дополнения» п. 1, 3)", () => {
    const p = parseParams(stand());
    expect([p.operation_outcome_every_ms, p.operation_outcome_max_delay_sec, p.operation_outcome_horizon_sec]).toEqual([1000, 30, 86400]);
    expect(parseParams({ ...stand(), operation_outcome_every_ms: 29_999 }).operation_outcome_every_ms).toBe(29_999);
    expect(() => parseParams({ ...stand(), operation_outcome_every_ms: 30_000 })).toThrow(/operation_outcome_every_ms не меньше operation_outcome_max_delay_sec/);
    expect(parseParams({ ...stand(), operation_outcome_horizon_sec: 60 }).operation_outcome_horizon_sec).toBe(60);
    expect(() => parseParams({ ...stand(), operation_outcome_horizon_sec: 59 })).toThrow(/operation_outcome_horizon_sec меньше двух operation_outcome_max_delay_sec/);
    for (const k of ["operation_outcome_every_ms", "operation_outcome_max_delay_sec", "operation_outcome_horizon_sec"]) {
      expect(() => parseParams({ ...stand(), [k]: 0 }), k).toThrow(new RegExp(`${k}:`));
    }
  });

  it("operation_reread_interval_sec меньше reservation_ttl_sec (РП55 п. 2)", () => {
    expect(parseParams(stand()).operation_reread_interval_sec).toBe(3600);
    expect(parseParams({ ...stand(), reservation_ttl_sec: 3601 }).operation_reread_interval_sec).toBe(3600);
    expect(() => parseParams({ ...stand(), reservation_ttl_sec: 3600 })).toThrow(/operation_reread_interval_sec не меньше reservation_ttl_sec/);
  });

  it("restore_budget_on_refund: true до PS-23 — отказ запуска (РП55 п. 4)", () => {
    expect(parseParams(stand()).restore_budget_on_refund).toBe(false);
    expect(() => parseParams({ ...stand(), restore_budget_on_refund: true })).toThrow(/restore_budget_on_refund: true не поддерживается до PS-23/);
  });

  it("participant_notify_allow_hosts — как event_subscription_allow_hosts: IP и повтор — отказ, пустой допустим", () => {
    expect(parseParams({ ...stand(), participant_notify_allow_hosts: [] }).participant_notify_allow_hosts).toEqual([]);
    for (const v of [["127.0.0.1"], ["a.stand", "a.stand"], ["A.stand"], "a.stand"]) {
      expect(() => parseParams({ ...stand(), participant_notify_allow_hosts: v }), JSON.stringify(v)).toThrow(/participant_notify_allow_hosts:/);
    }
  });

  it("upk_page_base_url — https:// и имя хоста без порта и пути; upk_sbp_enabled — булево (РП51 п. 10, 16)", () => {
    expect(parseParams(stand()).upk_page_base_url).toBe("https://upk.stand");
    expect(parseParams(stand()).upk_sbp_enabled).toBe(false);
    for (const v of ["http://upk.stand", "https://upk.stand/", "https://upk.stand/c", "https://upk.stand:443", "https://u@upk.stand", "https://UPK.stand", "https://127.0.0.1", "https://upk.stand?x=1", "upk.stand"]) {
      expect(() => parseParams({ ...stand(), upk_page_base_url: v }), v).toThrow(/upk_page_base_url:/);
    }
    expect(() => parseParams({ ...stand(), upk_sbp_enabled: "false" })).toThrow(/upk_sbp_enabled:/);
  });

  it("PARAMS_PATH описан в PARAMS.md", () => {
    expect(readFileSync("docs/core/PARAMS.md", "utf8")).toContain("`PARAMS_PATH`");
  });

  it("испорченный файл — отказ запуска", () => {
    const dir = mkdtempSync(join(tmpdir(), "params-"));
    const path = join(dir, "bad.json");
    writeFileSync(path, "{ не json");
    expect(() => loadParams(path)).toThrow(ParamsError);
    expect(() => loadParams(join(dir, "missing.json"))).toThrow(ParamsError);
  });
});
