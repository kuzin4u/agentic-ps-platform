// Векторы удержаний ядра против хранилища П3 Платформы (PS-20 ч. 2 К1.1, ядро v0.11.0, РП46 (г)): holdLedger() —
// то же подключение, что в рабочем сервере (память без базы, PgHoldLedger на PostgreSQL). Разделы holds и
// holds_set_limit (version 2). Прогон падает на неизвестном разделе или шаге (README ядра, «Тестовые векторы»):
// иначе новая операция ядра «проходила» бы без реализации у Платформы.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { HoldError, type AsyncHoldLedger, type Money } from "@kuzin4u/agentic-core";
import { afterAll, describe, expect, it } from "vitest";
import { holdLedger } from "../../src/state/index.js";
import { DATABASE_URL, openTestDb, type TestDb } from "../support/pg.js";

type Step = { op: [string, ...unknown[]]; error?: string; available: Money; account?: Record<string, number> };

const V = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../vectors/vectors.json", import.meta.resolve("@kuzin4u/agentic-core"))), "utf8"),
) as Record<string, unknown> & { version: number; holds: Step[]; holds_set_limit: Step[] };

/** Разделы, которые Платформа знает: holds и holds_set_limit — здесь, ed25519_weak_keys — registry-keys.test.ts. */
const KNOWN = ["version", "canonical", "journal", "journal_chain_genesis", "money", "holds", "holds_set_limit", "ed25519_weak_keys"];

async function run(L: AsyncHoldLedger, steps: Step[], account: string): Promise<void> {
  const ids: Record<string, string> = {};
  for (const step of steps) {
    const [op, ...a] = step.op;
    const where = JSON.stringify(step.op);
    try {
      if (op === "open") await L.openAccount(a[0] as string, a[1] as Money);
      else if (op === "setLimit") await L.setLimit(a[0] as string, a[1] as Money);
      else if (op === "reserve") ids[a[2] as string] = (await L.reserve(a[0] as string, a[1] as Money, a[2] as string, (a[3] as number) ?? null)).id;
      else if (op === "commit") await L.commit(ids[a[0] as string]!, a[1] as Money, (a[2] as boolean) ?? false);
      else if (op === "release") await L.release(ids[a[0] as string]!);
      else if (op === "expire") await L.expire(a[0] as number);
      else throw new Error(`векторы holds: неизвестный шаг ${where}`);
      expect(step.error ?? null, where).toBeNull();
    } catch (e) {
      if (!(e instanceof HoldError)) throw e;
      expect(e.code, where).toBe(step.error);
    }
    expect(await L.available(account), where).toEqual(step.available);
    if (step.account) expect(await L.account(account), where).toMatchObject(step.account);
  }
}

describe("векторы удержаний ядра v0.11.0 (PS-20 ч. 2 К1.1)", () => {
  it("разделы векторов известны Платформе, version — 2", () => {
    expect(V.version).toBe(2);
    expect(Object.keys(V).filter((k) => !KNOWN.includes(k)), "новый раздел векторов ядра без прогона Платформы").toEqual([]);
  });

  it("неизвестный шаг — отказ прогона, а не пропуск", async () => {
    await expect(run(holdLedger(), [{ op: ["freeze", "LIM-1"], available: { amount: 0, currency: "RUB" } }], "LIM-1")).rejects.toThrow(
      /неизвестный шаг/,
    );
  });

  it("holds — память", async () => run(holdLedger(), V.holds, "MND-1"));
  it("holds_set_limit — память (setLimit, LIMIT_BELOW_USED)", async () => run(holdLedger(), V.holds_set_limit, "LIM-1"));
});

// Шаг expire освобождает все истёкшие удержания таблицы — у каждого раздела своя схема.
describe.skipIf(!DATABASE_URL)("векторы удержаний ядра на PostgreSQL (PS-20 ч. 2 К1.1)", () => {
  const dbs: TestDb[] = [];
  const pg = async (label: string): Promise<AsyncHoldLedger> => {
    const db = await openTestDb(label);
    dbs.push(db);
    return holdLedger(db.pool);
  };
  afterAll(async () => {
    for (const db of dbs) await db.close();
  });

  it("holds — PgHoldLedger", async () => run(await pg("vec_holds"), V.holds, "MND-1"));
  it("holds_set_limit — PgHoldLedger", async () => run(await pg("vec_setlimit"), V.holds_set_limit, "LIM-1"));
});
