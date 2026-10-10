// Инвариант 1: номера карты нет ни в канонической модели, ни в ПАО — только token_ref, funding_ref, account_link_ref.
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";

// Слова и последовательности слов, которыми называют номер карты и его спутники.
const FORBIDDEN_WORDS = new Set([
  "pan",
  "cvv",
  "cvv2",
  "cvc",
  "cvc2",
  "expiry",
  "exp",
  "expiration",
  "track1",
  "track2",
  "pin",
]);
const FORBIDDEN_SEQUENCES = [
  ["card", "number"],
  ["card", "no"],
  ["card", "num"],
  ["account", "number"],
  ["security", "code"],
];

/** Слова имени: разбиение по _, -, . и смене регистра (cardNumber → card, number; PANRef → pan, ref). */
const words = (name: string): string[] =>
  name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);

const forbidden = (name: string): boolean => {
  const w = words(name);
  if (w.some((x) => FORBIDDEN_WORDS.has(x))) return true;
  // Слитные формы (cardnumber, cardno) — по склейке соседних слов и внутри одного слова.
  const glued = w.join("");
  return FORBIDDEN_SEQUENCES.some(
    (seq) =>
      w.some((_, i) => seq.every((s, j) => w[i + j] === s)) ||
      w.some((x) => x === seq.join("")) ||
      glued === seq.join(""),
  );
};

/** Имена полей схем, параметров и заголовков спецификации OpenAPI. */
function fieldNames(spec: unknown): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (node: unknown, path: string): void => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${path}[${i}]`));
      return;
    }
    if (!node || typeof node !== "object") return;
    const obj = node as Record<string, unknown>;
    if (typeof obj.name === "string" && typeof obj.in === "string")
      out.set(obj.name, `${path}.name`);
    if (path === ".paths") {
      for (const p of Object.keys(obj))
        for (const m of p.matchAll(/\{([^}]+)\}/g))
          out.set(m[1] as string, `paths.${p}`);
    }
    for (const [k, v] of Object.entries(obj)) {
      if (
        (k === "properties" || k === "headers") &&
        v &&
        typeof v === "object"
      ) {
        for (const f of Object.keys(v)) out.set(f, `${path}.${k}.${f}`);
      }
      if (k === "required" && Array.isArray(v))
        for (const f of v)
          if (typeof f === "string") out.set(f, `${path}.required`);
      walk(v, `${path}.${k}`);
    }
  };
  walk(spec, "");
  return out;
}

const SPECS = [
  "docs/core/processing-interface.yaml",
  "docs/core/agent-protocol.yaml",
];

describe("номера карты нет в схемах (инвариант 1)", () => {
  it("детектор различает слова, а не подстроки", () => {
    for (const n of [
      "pan",
      "PANRef",
      "card_number",
      "cardNumber",
      "cardnumber",
      "CardNo",
      "card-num",
      "primary_account_number",
      "account_number",
      "cvv2",
      "security_code",
      "expiry",
      "exp_month",
      "expiration_date",
      "track2",
      "pin_block",
    ]) {
      expect(forbidden(n), n).toBe(true);
    }
    for (const n of [
      "company",
      "expires_at",
      "span_id",
      "pinned",
      "token_ref",
      "funding_ref",
      "account_link_ref",
      "card_token",
      "account_ref",
    ]) {
      expect(forbidden(n), n).toBe(false);
    }
  });

  it.each(SPECS)("%s: ни одно имя поля, параметра или заголовка", (file) => {
    const spec = parse(readFileSync(file, "utf8"), { maxAliasCount: -1 });
    const names = fieldNames(spec);
    expect(names.size).toBeGreaterThan(20);
    const hits = [...names]
      .filter(([n]) => forbidden(n))
      .map(([n, at]) => `${n} @ ${at}`);
    expect(hits).toEqual([]);
  });
});
