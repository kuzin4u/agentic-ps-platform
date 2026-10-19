// Полнота реестров кодов Платформы в формате /diag ядра (РП42 п. 3, К17 п. 3): код без записи — красный тест.
// Три реестра по компоненту: PAO_DIAG ядра, PI_DIAG, PLATFORM_DIAG (РП42 п. 2).
import { checkDiagRegistry, type DiagProblem, type DiagRegistry } from "@kuzin4u/agentic-core/diag";
import { PAO_RETRY_ACTION } from "@kuzin4u/agentic-core/pao";
import { describe, expect, it } from "vitest";
import {
  DECISION_REASON,
  PAO_DIAG,
  PAO_ERROR_CODES,
  PAO_ERRORS,
  PI_DIAG,
  PLATFORM_DIAG,
  PLATFORM_DIAG_CODES,
  PLATFORM_STATE_CODES,
  STARTUP_CODES,
} from "../../src/shared/index.js";
import { STATE_CODES } from "../../src/state/index.js";

/** Замечание — код и поле записи, чтобы красный тест сразу называл, что дописать. */
const describeProblems = (ps: readonly DiagProblem[]): string =>
  ps.map((p) => `${p.code}: ${p.entry}${p.field ? ` (${p.field})` : ""}`).join("; ");

const REGISTRIES: readonly { name: string; codes: readonly string[]; registry: DiagRegistry; component: string }[] = [
  { name: "PI_DIAG ← DECISION_REASON", codes: DECISION_REASON, registry: PI_DIAG, component: "pi" },
  { name: "PLATFORM_DIAG ← коды П3 вне ПАО и STARTUP_*", codes: PLATFORM_DIAG_CODES, registry: PLATFORM_DIAG, component: "platform" },
  { name: "PAO_DIAG ядра ← PAO_ERROR_CODES Платформы", codes: PAO_ERROR_CODES, registry: PAO_DIAG, component: "pao" },
];

describe("реестры кодов Платформы (РП42)", () => {
  for (const r of REGISTRIES) {
    it(`${r.name}: каждому коду — одна запись по формату К17, лишних нет`, () => {
      const problems = checkDiagRegistry(r.codes, r.registry);
      expect(problems, describeProblems(problems)).toEqual([]);
    });

    it(`${r.name}: component = ${r.component}`, () => {
      const wrong = Object.values(r.registry).filter((e) => e.component !== r.component).map((e) => e.code);
      expect(wrong).toEqual([]);
    });
  }

  it("каждый код П3 — код ПАО или запись PLATFORM_DIAG, третьего нет (РП42 п. 3)", () => {
    const pao = new Set<string>(PAO_ERROR_CODES);
    const platform = new Set<string>(PLATFORM_STATE_CODES);
    const orphan = STATE_CODES.filter((c) => !pao.has(c) && !platform.has(c));
    expect(orphan, `коды П3 без записи: ${orphan.join(", ")}`).toEqual([]);
    // Коды П3 вне ПАО — ровно те, что у П3 есть и в ПАО нет: запись под код, которого уже нет, — тоже красный.
    expect([...PLATFORM_STATE_CODES].sort()).toEqual(STATE_CODES.filter((c) => !pao.has(c)).sort());
  });

  it("PAO_DIAG: действие — по retry из x-pao-errors Платформы", () => {
    const wrong = PAO_ERRORS.filter((e) => PAO_DIAG[e.code].action !== PAO_RETRY_ACTION[e.retry]).map((e) => e.code);
    expect(wrong).toEqual([]);
  });

  it("STARTUP_*: дефект сборки — platform, after_fix; остальные — environment, after_human (РП42 п. 4)", () => {
    const build = new Set(["STARTUP_PAO_SPEC_MISMATCH", "STARTUP_DIAG_INCOMPLETE"]);
    for (const code of STARTUP_CODES) {
      const e = PLATFORM_DIAG[code];
      expect({ code, source: e.source, action: e.action }).toEqual(
        build.has(code)
          ? { code, source: ["platform"], action: "after_fix" }
          : { code, source: ["environment"], action: "after_human" },
      );
    }
  });

  it("коды ПИ — для процессинга и эквайрера: реквизит агента они не исправят — CREDENTIAL_INVALID stop", () => {
    expect(PI_DIAG.CREDENTIAL_INVALID.action).toBe("stop");
  });

  it("коды ПИ и ПАО с одним именем — разные записи разных компонентов (РП42 п. 2)", () => {
    const shared = DECISION_REASON.filter((c) => (PAO_ERROR_CODES as readonly string[]).includes(c));
    expect(shared).toHaveLength(10);
    for (const c of shared) expect(PI_DIAG[c]).not.toBe(PAO_DIAG[c as keyof typeof PAO_DIAG]);
  });
});
