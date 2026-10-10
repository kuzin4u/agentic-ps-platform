import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import {
  DECISIONS,
  DECISION_REASONS,
  DecisionPairError,
  parseDecision,
  parseDecisionKind,
  parseDecisionReason,
  UnknownCodeError,
} from "../../src/shared/index.js";

const pi = parse(readFileSync("docs/core/processing-interface.yaml", "utf8"));

/** Таблица ПИ §6: код Платформы → колонка «Код ответа ОПКЦ»; групповая строка MANDATE_* раскрывается. */
const PI6 = ((): Map<string, string> => {
  const doc = readFileSync("docs/core/PROCESSING-INTERFACE.md", "utf8");
  const from = doc.indexOf("## 6.");
  const to = doc.indexOf("## 7.");
  if (from < 0 || to < from) throw new Error("в ПИ нет раздела 6");
  const rows = new Map<string, string>();
  for (const line of doc.slice(from, to).split("\n")) {
    const cells = line.split("|").map((c) => c.trim());
    if (!/^[A-Z_]+( \/ [A-Z_]+)*$/.test(cells[1] ?? "")) continue;
    const [first, ...rest] = (cells[1] as string).split(" / ");
    const prefix = `${(first as string).split("_")[0]}_`; // MANDATE_NOT_FOUND / EXPIRED → MANDATE_EXPIRED
    for (const code of [first as string, ...rest.map((r) => prefix + r)]) rows.set(code, cells[3] ?? "");
  }
  return rows;
})();

/** Группа смысла кода ОПКЦ — текст в «»; голый [альбом] — группа не назначена. */
const group = (code: string): string => {
  const cell = PI6.get(code);
  if (cell === undefined) throw new Error(`${code} нет в ПИ §6`);
  return /«([^»]+)»/.exec(cell)?.[1] ?? "";
};

describe("коды решений ADP", () => {
  it("перечни совпадают с processing-interface.yaml", () => {
    const d = pi.components.schemas.Decision.properties;
    expect([...DECISIONS]).toEqual(d.decision.enum);
    expect([...DECISION_REASONS]).toEqual(d.reason.enum.filter((v: unknown) => v !== null));
  });

  it("коды таблицы ПИ §6 совпадают с перечнем reason (РП19 п. 1)", () => {
    expect([...PI6.keys()].sort()).toEqual([...DECISION_REASONS].sort());
  });

  it("агентские отказы отделены от отказа по лимиту (A1 п. 5.3)", () => {
    const limit = group("LIMIT_EXCEEDED");
    expect(limit).not.toBe("");
    for (const r of ["AOI_MISSING", "AGENT_UNKNOWN"]) {
      expect(group(r), r).not.toBe("");
      expect(group(r), r).not.toBe(limit);
    }
  });

  it("группа ОПКЦ не назначена — ждём альбомов (расхождение №8)", () => {
    // Когда группа появится, тест покраснеет: перенести код в проверку выше и закрыть расхождение.
    for (const r of ["AOI_MISMATCH", "AGENT_SUSPENDED", "CREDENTIAL_INVALID"]) {
      expect(PI6.get(r), r).toBe("`[альбом]`");
    }
  });

  it.todo("агентские отказы отделены от отказа по фроду (A1 п. 5.3): в ПИ §6 нет кода фродового отказа");

  it("неизвестный код — отказ, не догадка (A3 п. 4.5)", () => {
    expect(parseDecisionKind("APPROVE")).toBe("APPROVE");
    expect(() => parseDecisionKind("SOFT_APPROVE")).toThrow(UnknownCodeError);
    expect(() => parseDecisionReason(null)).toThrow(UnknownCodeError);
    expect(() => parseDecisionReason("approve")).toThrow(UnknownCodeError);
  });
});

describe("пары «решение — причина» (РП19)", () => {
  const adpDecline: readonly string[] = DECISION_REASONS.filter((r) => r !== "CONFIRMATION_REQUIRED" && r !== "ADP_UNAVAILABLE");

  it("ADP: допустимые пары принимаются", () => {
    expect(parseDecision({ decision: "APPROVE", reason: null }, "adp")).toEqual({ decision: "APPROVE", reason: null });
    expect(parseDecision({ decision: "BYPASS" }, "adp")).toEqual({ decision: "BYPASS", reason: null });
    expect(parseDecision({ decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED" }, "adp").reason).toBe(
      "CONFIRMATION_REQUIRED",
    );
    for (const r of adpDecline) expect(parseDecision({ decision: "DECLINE", reason: r }, "adp").reason).toBe(r);
  });

  it("ADP: все прочие пары — отказ", () => {
    let rejected = 0;
    for (const d of DECISIONS) {
      for (const r of [null, ...DECISION_REASONS]) {
        const ok =
          ((d === "APPROVE" || d === "BYPASS") && r === null) ||
          (d === "CONFIRMATION_REQUIRED" && r === "CONFIRMATION_REQUIRED") ||
          (d === "DECLINE" && r !== null && adpDecline.includes(r));
        if (ok) continue;
        expect(() => parseDecision({ decision: d, reason: r }, "adp"), `${d}/${r}`).toThrow(DecisionPairError);
        rejected++;
      }
    }
    expect(rejected).toBeGreaterThan(0);
  });

  it("ADP_UNAVAILABLE ставит только процессинг", () => {
    expect(() => parseDecision({ decision: "DECLINE", reason: "ADP_UNAVAILABLE" }, "adp")).toThrow(DecisionPairError);
    expect(parseDecision({ decision: "DECLINE", reason: "ADP_UNAVAILABLE" }, "processing")).toEqual({
      decision: "DECLINE",
      reason: "ADP_UNAVAILABLE",
    });
    expect(() => parseDecision({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" }, "processing")).toThrow(
      DecisionPairError,
    );
    expect(() => parseDecision({ decision: "APPROVE", reason: null }, "processing")).toThrow(DecisionPairError);
  });

  it("DECLINE без причины, неизвестный код, не объект — отказ (A3 п. 4.5)", () => {
    expect(() => parseDecision({ decision: "DECLINE" }, "adp")).toThrow(DecisionPairError);
    expect(() => parseDecision({ decision: "DECLINE", reason: "TEAPOT" }, "adp")).toThrow(UnknownCodeError);
    expect(() => parseDecision({ decision: "MAYBE", reason: null }, "adp")).toThrow(UnknownCodeError);
    expect(() => parseDecision(null, "adp")).toThrow(UnknownCodeError);
    expect(() => parseDecision([], "adp")).toThrow(UnknownCodeError);
  });

  it("решение из прототипа не подставляется", () => {
    const raw = Object.create({ decision: "APPROVE" }) as Record<string, unknown>;
    raw.reason = null;
    expect(() => parseDecision(raw, "adp")).toThrow(UnknownCodeError);
  });

  it("неизвестный источник — отказ", () => {
    for (const src of ["ADP", undefined, "issuer"]) {
      expect(() => parseDecision({ decision: "APPROVE", reason: null }, src as never), String(src)).toThrow(
        UnknownCodeError,
      );
    }
  });

  it("причина из прототипа не подставляется", () => {
    const raw = Object.create({ reason: "LIMIT_EXCEEDED" }) as Record<string, unknown>;
    raw.decision = "DECLINE";
    expect(() => parseDecision(raw, "adp")).toThrow(DecisionPairError);
  });
});

describe("каноническая модель", () => {
  it("инструмент — только ссылками", () => {
    const props = Object.keys(pi.components.schemas.Instrument.properties);
    expect(props.filter((p) => !["kind", "cryptogram", "issuer_id"].includes(p)).every((p) => p.endsWith("_ref"))).toBe(
      true,
    );
  });
});
