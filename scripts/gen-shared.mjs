// Генератор src/shared из спецификаций Платформы (PS-02).
// processing-interface.yaml → канонические типы и перечни; agent-protocol.yaml (x-pao-errors) → таблица ошибок ПАО.
// `node scripts/gen-shared.mjs` — записать; `--check` — сверить с файлами, не записывая.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { parse } from "yaml";

const PI = "docs/core/processing-interface.yaml";
const PAO = "docs/core/agent-protocol.yaml";
const OUT_CANONICAL = "src/shared/canonical.generated.ts";
const OUT_ERRORS = "src/shared/pao-errors.generated.ts";
const REF = "#/components/schemas/";

function load(path) {
  const raw = readFileSync(path, "utf8");
  return { sha: createHash("sha256").update(raw).digest("hex"), spec: parse(raw, { maxAliasCount: -1 }) };
}

const refName = (ref) => {
  if (!ref.startsWith(REF)) throw new Error(`UNSUPPORTED_REF ${ref}`);
  return ref.slice(REF.length);
};
const key = (k) => (/^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k));
const doc = (s, pad) => (s.description ? `${pad}/** ${s.description} */\n` : "");
const constName = (schema, prop) => `${schema.replace(/([a-z])([A-Z])/g, "$1_$2")}_${prop}`.toUpperCase();

function tsType(s, pad = "") {
  if (s.$ref) return refName(s.$ref);
  let t;
  if (s.enum) t = s.enum.map((v) => (v === null ? "null" : JSON.stringify(v))).join(" | ");
  else if (s.type === "string") t = "string";
  else if (s.type === "integer" || s.type === "number") t = "number";
  else if (s.type === "boolean") t = "boolean";
  else if (s.type === "array") t = `Array<${tsType(s.items, pad)}>`;
  else if (s.type === "object" || s.properties) t = objectType(s, pad);
  else throw new Error(`UNSUPPORTED_SCHEMA ${JSON.stringify(s)}`);
  if (s.nullable && !(s.enum ?? []).includes(null)) t += " | null";
  return t;
}

function objectType(s, pad) {
  if (!s.properties) return "Record<string, unknown>";
  const req = new Set(s.required ?? []);
  const inner = pad + "  ";
  const lines = Object.entries(s.properties).map(
    ([k, p]) => `${doc(p, inner)}${inner}${key(k)}${req.has(k) ? "" : "?"}: ${tsType(p, inner)};`,
  );
  return `{\n${lines.join("\n")}\n${pad}}`;
}

function canonical() {
  const { sha, spec } = load(PI);
  const schemas = spec.components.schemas;
  const out = [];
  out.push(`// Сгенерировано scripts/gen-shared.mjs из ${PI} — не править вручную.`);
  out.push(`// ${spec.info.title} ${spec.info.version}, sha-256 ${sha}`);
  out.push("// Номера полей и кодов внешних форматов здесь нет: только каноническая модель [альбом] (РП6).");
  out.push("");
  out.push(`export const PI_VERSION = ${JSON.stringify(spec.info.version)};`);
  out.push(`export const PI_SPEC_SHA256 = ${JSON.stringify(sha)};`);
  out.push("");
  for (const [name, s] of Object.entries(schemas)) {
    const body = tsType(s);
    out.push(`${doc(s, "")}export interface ${name} ${body}`, "");
  }
  out.push("// Перечни значений: «СХЕМА_ПОЛЕ».");
  for (const [name, s] of Object.entries(schemas)) {
    for (const [prop, p] of Object.entries(s.properties ?? {})) {
      if (!p.enum) continue;
      const values = p.enum.filter((v) => v !== null);
      out.push(`export const ${constName(name, prop)} = ${JSON.stringify(values)} as const;`);
    }
  }
  out.push("");
  out.push("/** components.schemas как в спецификации — для проверок в тестах. */");
  out.push(`export const PI_SCHEMAS: Record<string, unknown> = ${JSON.stringify(schemas, null, 2)};`);
  out.push("");
  return out.join("\n");
}

function paoErrors() {
  const { sha, spec } = load(PAO);
  const errors = spec["x-pao-errors"]?.errors;
  const RETRY = spec.components.schemas.Error?.properties?.retry?.enum;
  if (!Array.isArray(RETRY) || RETRY.length === 0) throw new Error(`${PAO}: нет Error.retry.enum`);
  if (!Array.isArray(errors) || errors.length === 0) throw new Error(`${PAO}: нет x-pao-errors.errors`);
  const enumCodes = spec.components.schemas.ErrorCode?.enum ?? [];
  const seen = new Set();
  for (const e of errors) {
    if (typeof e.code !== "string" || !Number.isInteger(e.http) || !RETRY.includes(e.retry)) {
      throw new Error(`${PAO}: неверная запись x-pao-errors ${JSON.stringify(e)}`);
    }
    if (seen.has(e.code)) throw new Error(`${PAO}: повтор кода ${e.code}`);
    seen.add(e.code);
  }
  const missing = enumCodes.filter((c) => !seen.has(c));
  const extra = [...seen].filter((c) => !enumCodes.includes(c));
  if (missing.length || extra.length) {
    throw new Error(`${PAO}: x-pao-errors не совпадает с ErrorCode (нет: ${missing}; лишние: ${extra})`);
  }
  const rows = errors.map((e) => ({ code: e.code, http: e.http, retry: e.retry, description: e.description }));
  const out = [];
  out.push(`// Сгенерировано scripts/gen-shared.mjs из ${PAO} (x-pao-errors) — не править вручную (РП16).`);
  out.push(`// ${spec.info.title} ${spec.info.version}, sha-256 ${sha}`);
  out.push("");
  out.push(`export const PAO_SPEC_VERSION = ${JSON.stringify(spec.info.version)};`);
  out.push(`export const PAO_SPEC_SHA256 = ${JSON.stringify(sha)};`);
  out.push(`export const PAO_RETRY_VALUES = ${JSON.stringify(RETRY)} as const;`);
  out.push(`export const PAO_ERROR_CODES = ${JSON.stringify(rows.map((r) => r.code))} as const;`);
  out.push("");
  out.push("export type PaoRetry = (typeof PAO_RETRY_VALUES)[number];");
  out.push("export type PaoErrorCode = (typeof PAO_ERROR_CODES)[number];");
  out.push("export interface PaoErrorSpec {");
  out.push("  readonly code: PaoErrorCode;");
  out.push("  readonly http: number;");
  out.push("  readonly retry: PaoRetry;");
  out.push("  readonly description: string;");
  out.push("}");
  out.push("");
  out.push(`export const PAO_ERRORS: readonly PaoErrorSpec[] = ${JSON.stringify(rows, null, 2)};`);
  out.push("");
  return out.join("\n");
}

const outputs = [
  [OUT_CANONICAL, canonical()],
  [OUT_ERRORS, paoErrors()],
];

if (process.argv.includes("--check")) {
  const problems = [];
  for (const [path, text] of outputs) {
    let current = "";
    try {
      current = readFileSync(path, "utf8");
    } catch {
      /* нет файла */
    }
    if (current !== text) problems.push(`${path} устарел: npm run gen:shared`);
  }
  if (problems.length) {
    console.error(problems.join("\n"));
    process.exit(1);
  }
  console.log("src/shared соответствует спецификациям");
} else {
  for (const [path, text] of outputs) {
    writeFileSync(path, text);
    console.log(`${path} записан`);
  }
}
