import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import {
  DECISIONS,
  DECISION_REASONS,
  PI_SCHEMAS,
  isDecisionReason,
  parseDecisionKind,
  parseDecisionReason,
  UnknownCodeError,
} from "../../src/shared/index.js";

const pi = parse(readFileSync("docs/core/processing-interface.yaml", "utf8"));

describe("коды решений ADP", () => {
  it("перечни совпадают с processing-interface.yaml", () => {
    const d = pi.components.schemas.Decision.properties;
    expect([...DECISIONS]).toEqual(d.decision.enum);
    expect([...DECISION_REASONS]).toEqual(d.reason.enum.filter((v: unknown) => v !== null));
  });

  it("каждый код причины описан в ПИ §6", () => {
    const doc = readFileSync("docs/core/PROCESSING-INTERFACE.md", "utf8");
    const table = doc.slice(doc.indexOf("## 6."), doc.indexOf("## 7."));
    for (const r of DECISION_REASONS) {
      const named = table.includes(r) || (r.startsWith("MANDATE_") && table.includes(r.replace("MANDATE_", "")));
      expect(named, r).toBe(true);
    }
  });

  it("агентские отказы отделены от лимита и фрода (A1 п. 5.3)", () => {
    for (const r of ["AOI_MISSING", "AGENT_UNKNOWN", "AGENT_SUSPENDED", "LIMIT_EXCEEDED"]) {
      expect(isDecisionReason(r)).toBe(true);
    }
  });

  it("неизвестный код — отказ, не догадка (A3 п. 4.5)", () => {
    expect(parseDecisionKind("APPROVE")).toBe("APPROVE");
    expect(() => parseDecisionKind("SOFT_APPROVE")).toThrow(UnknownCodeError);
    expect(() => parseDecisionReason(null)).toThrow(UnknownCodeError);
    expect(() => parseDecisionReason("approve")).toThrow(UnknownCodeError);
  });
});

describe("каноническая модель", () => {
  it("номера карты нет ни в одной схеме (инвариант 1)", () => {
    const forbidden = /pan|card_?number|cvv|cvc|expiry/i;
    const walk = (node: unknown, path: string): void => {
      if (node && typeof node === "object") {
        for (const [k, v] of Object.entries(node)) {
          expect(forbidden.test(k), `${path}.${k}`).toBe(false);
          walk(v, `${path}.${k}`);
        }
      }
    };
    walk(PI_SCHEMAS, "schemas");
  });

  it("инструмент — только ссылками", () => {
    const props = Object.keys(pi.components.schemas.Instrument.properties);
    expect(props.filter((p) => !["kind", "cryptogram", "issuer_id"].includes(p)).every((p) => p.endsWith("_ref"))).toBe(
      true,
    );
  });
});
