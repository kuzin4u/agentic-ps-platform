// Адрес agentic-core в package.json и package-lock.json — только git+https (решение владельца 13.10.2026, «К CI»).
// `npm install` переписывает адрес в `github:` и `resolved` в `git+ssh` (регрессия npm, дважды в сессии 8 и в PS-05 К1.1):
// в CI без ключа SSH такая установка падает, а у агента, ставящего платформу по git+https, расходится с lock.
// Тест — в `npm test`, то есть и в CI, и локально до коммита.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = resolve(import.meta.dirname, "../..");
const CORE = "@kuzin4u/agentic-core";
const CORE_URL = /^git\+https:\/\/github\.com\/kuzin4u\/agentic-core\.git#v\d+\.\d+\.\d+$/;
const CORE_RESOLVED = /^git\+https:\/\/github\.com\/kuzin4u\/agentic-core\.git#[0-9a-f]{40}$/;
/** Адреса, которые npm подставляет сам: SSH и сокращение github:. */
const FORBIDDEN = /git\+ssh:|"github:|ssh:\/\/git@/;

const read = (name: string): string => readFileSync(resolve(ROOT, name), "utf8");

interface Lock {
  readonly packages: Record<string, { dependencies?: Record<string, string>; resolved?: string; version?: string }>;
}

describe("адрес agentic-core — только git+https", () => {
  const pkg = JSON.parse(read("package.json")) as { dependencies: Record<string, string> };
  const lockText = read("package-lock.json");
  const lock = JSON.parse(lockText) as Lock;

  it("package.json: git+https на тег vX.Y.Z", () => {
    expect(pkg.dependencies[CORE]).toMatch(CORE_URL);
  });

  it("package-lock.json: корневая запись совпадает с package.json, resolved — git+https на коммит", () => {
    expect(lock.packages[""]?.dependencies?.[CORE]).toBe(pkg.dependencies[CORE]);
    expect(lock.packages[`node_modules/${CORE}`]?.resolved).toMatch(CORE_RESOLVED);
  });

  it("в package.json и package-lock.json нет git+ssh и github:", () => {
    expect(read("package.json")).not.toMatch(FORBIDDEN);
    expect(lockText).not.toMatch(FORBIDDEN);
  });
});
