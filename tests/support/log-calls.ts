// Поиск вызовов журнала в src для стражей: server-log-guard (РП64 п. 9) и journal-scan (Ж4, SEC-2 ч. 2).
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect } from "vitest";

/** Начало вызова журнала: log(…), log?.(…), log.warn(…), log[level](…), logger.info(…). */
export const LOG_CALL = /\b(?:log|logger)(?:\?\.)?(?:\.(?:trace|debug|info|warn|error|fatal)|\[[^\]\n]+\])?(?:\?\.)?\(/g;

/** Файлы .ts из src: [путь относительно src, текст]. */
export function srcFiles(): [string, string][] {
  const root = join(import.meta.dirname, "../../src");
  const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));
  expect(files.length).toBeGreaterThan(50);
  return files.map((f) => [f, readFileSync(join(root, f), "utf8")]);
}

/** Вызовы по началу start: текст начала и аргументы до парной скобки (скобки внутри аргументов учитываются). */
export function* calls(text: string, start: RegExp): Generator<[string, string]> {
  for (const m of text.matchAll(start)) {
    const from = m.index + m[0].length;
    let depth = 1;
    let i = from;
    for (; i < text.length && depth > 0; i++) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")") depth--;
    }
    yield [m[0], text.slice(from, i - 1)];
  }
}
