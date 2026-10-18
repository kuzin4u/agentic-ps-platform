// РП25 п. 3: рабочий сервер не импортирует стенд. Стенд допускает агента с оператором от вызывающего (обход №9);
// граница доказывается обходом графа импортов src/main.ts по AST компилятора TypeScript, а не комментарием.
// Fail-closed: всё, что обход не может разрешить однозначно, — нарушение, а не пропуск:
// самоссылка на пакет (agentic-ps-platform/…), #-импорты, абсолютные пути и file:, импорт или require
// с нелитеральным аргументом, createRequire.
import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const ROOT = resolve(import.meta.dirname, "../..");
const PACKAGE_NAME = (JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")) as { name: string }).name;

interface Scan {
  readonly specifiers: string[];
  readonly violations: string[];
}

/** Спецификаторы модулей файла и конструкции, которые обход разрешить не может. */
function scan(fileName: string, text: string): Scan {
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true);
  const specifiers: string[] = [];
  const violations: string[] = [];
  const at = (n: ts.Node): string => `${fileName}:${sf.getLineAndCharacterOfPosition(n.getStart()).line + 1}`;
  const take = (arg: ts.Expression | undefined, n: ts.Node, what: string): void => {
    if (arg && (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))) specifiers.push(arg.text);
    else violations.push(`${at(n)}: ${what} с нелитеральным аргументом`);
  };
  const visit = (n: ts.Node): void => {
    if ((ts.isImportDeclaration(n) || ts.isExportDeclaration(n)) && n.moduleSpecifier) {
      take(n.moduleSpecifier, n, "импорт");
    } else if (ts.isImportEqualsDeclaration(n) && ts.isExternalModuleReference(n.moduleReference)) {
      take(n.moduleReference.expression, n, "import = require");
    } else if (ts.isCallExpression(n)) {
      if (n.expression.kind === ts.SyntaxKind.ImportKeyword) take(n.arguments[0], n, "import()");
      else if (ts.isIdentifier(n.expression) && n.expression.text === "require") take(n.arguments[0], n, "require()");
    } else if (ts.isIdentifier(n) && n.text === "createRequire") {
      violations.push(`${at(n)}: createRequire`);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return { specifiers, violations };
}

/** Спецификатор, который обход не разрешает: самоссылка, #-импорт, абсолютный путь, URL. */
function forbiddenSpecifier(spec: string): boolean {
  return (
    spec === PACKAGE_NAME ||
    spec.startsWith(`${PACKAGE_NAME}/`) ||
    spec.startsWith("#") ||
    spec.startsWith("/") ||
    /^[a-z][a-z0-9+.-]*:/i.test(spec.replace(/^node:/, "")) // file:, data:, http: — но не node:
  );
}

/** Файлы проекта, достижимые из entry, и нарушения по пути. */
function importGraph(entry: string): { files: Set<string>; violations: string[] } {
  const seen = new Set<string>();
  const violations: string[] = [];
  const queue = [resolve(ROOT, entry)];
  while (queue.length) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const rel = relative(ROOT, file);
    const found = scan(rel, readFileSync(file, "utf8"));
    violations.push(...found.violations);
    for (const spec of found.specifiers) {
      if (forbiddenSpecifier(spec)) {
        violations.push(`${rel}: запрещённый спецификатор ${spec}`);
        continue;
      }
      if (!spec.startsWith(".")) continue; // внешние пакеты и node: — вне графа проекта
      const base = resolve(dirname(file), spec);
      const candidates = [base.replace(/\.js$/, ".ts"), base, `${base}.ts`, resolve(base, "index.ts")];
      const hit = candidates.find((c) => c.endsWith(".ts") && existsSync(c));
      if (!hit) violations.push(`${rel}: не разрешён импорт ${spec}`);
      else queue.push(hit);
    }
  }
  return { files: new Set([...seen].map((f) => relative(ROOT, f))), violations };
}

const inStand = (f: string): boolean => f.startsWith("src/stand/");

describe("РП25: граница «стенд ≠ рабочий сервер»", () => {
  it("граф импортов src/main.ts не содержит src/stand и неразрешимых импортов", () => {
    const { files, violations } = importGraph("src/main.ts");
    // Обход не пустой: в графе есть сервер, шлюз ПАО и реестр — иначе проверка ничего не доказывает.
    expect(files).toContain("src/server.ts");
    expect(files).toContain("src/pao/verify.ts");
    expect(files).toContain("src/registry/registry.ts");
    expect(violations).toEqual([]);
    expect([...files].filter(inStand)).toEqual([]);
    // Эмуляторы окружения и фикстуры (PS-12) — тоже не часть рабочего сервера.
    expect([...files].filter((f) => f.startsWith("src/env/") || f.startsWith("src/fixtures/"))).toEqual([]);
  });

  it("обход видит стенд, если он импортирован (контроль самой проверки)", () => {
    expect([...importGraph("tests/support/stand.ts").files].filter(inStand).sort()).toEqual([
      "src/stand/dns.ts",
      "src/stand/index.ts",
      "src/stand/merchants.ts",
    ]);
  });

  describe("контроль: обходы границы — нарушение, а не пропуск", () => {
    const cases: [string, string][] = [
      ["самоссылка на пакет", `import { createStand } from "${PACKAGE_NAME}/stand";`],
      ["самоссылка через import()", `await import("${PACKAGE_NAME}/stand");`],
      ["#-импорт", `import "#stand";`],
      ["абсолютный путь", `import "/repo/dist/stand/index.js";`],
      ["file: URL", `await import("file:///repo/dist/stand/index.js");`],
      ["import() с шаблонной строкой", "const x = 'index'; await import(`../stand/${x}.js`);"],
      ["import() от new URL", 'await import(new URL("./stand/index.js", import.meta.url).href);'],
      ["createRequire", 'import { createRequire } from "node:module"; createRequire(import.meta.url)("x");'],
      ["require с переменной", "const p = '../stand/index.js'; require(p);"],
    ];
    it.each(cases)("%s", (_name, code) => {
      const found = scan("probe.ts", code);
      const bad = found.violations.length + found.specifiers.filter(forbiddenSpecifier).length;
      expect(bad).toBeGreaterThan(0);
    });

    it("литеральные импорты разбираются: относительный, require, реэкспорт, пакет, node:", () => {
      const code = [
        'import a from "./a.js";',
        'export * from "../b.js";',
        'const c = require("./c.js");',
        'await import("fastify");',
        'import "node:fs";',
      ].join("\n");
      const found = scan("probe.ts", code);
      expect(found.violations).toEqual([]);
      expect(found.specifiers).toEqual(["./a.js", "../b.js", "./c.js", "fastify", "node:fs"]);
      expect(found.specifiers.filter(forbiddenSpecifier)).toEqual([]);
    });
  });
});
