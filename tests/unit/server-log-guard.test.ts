// РП63 п. 12–13 (PS-05в ч. 1, решения владельца 26.10, PR #74): журнал без текста исключения и сырого адреса —
// перехват hooks.logMethod; уровень журнала не ниже info — отказ запуска; уровень маршрута и смена уровня в коде — страж.
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer, pathlessLogArgs } from "../../src/server.js";

const mark = `mark${randomUUID().replaceAll("-", "")}`;

type Entry = Record<string, unknown>;

function logged(extra: Record<string, unknown> = {}): { app: FastifyInstance; entries: () => Entry[]; text: () => string } {
  const lines: string[] = [];
  const app = buildServer({ env: "dev", logger: { level: "info", stream: { write: (l: string) => void lines.push(l) }, ...extra } });
  return { app, entries: () => lines.map((l) => JSON.parse(l) as Entry), text: () => lines.join("\n") };
}

describe("перехват записей журнала (РП63 п. 12)", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it("5xx вне /pao, исключение с путём в message, cause и AggregateError — меток пути нет, сообщение «исключение»", async () => {
    const j = logged();
    app = j.app;
    app.get("/test/boom/:secret", async (req) => {
      const { secret } = req.params as { secret: string };
      throw new Error(`сбой /test/boom/${secret}`, { cause: new Error(`вложенное ${secret}`) });
    });
    app.get("/test/agg/:secret", async (req) => {
      const { secret } = req.params as { secret: string };
      throw new AggregateError([new Error(`первое ${secret}`), new TypeError(`второе ${secret}`)], `сводное ${secret}`);
    });
    expect((await app.inject({ url: `/test/boom/${mark}?q=${mark}` })).statusCode).toBe(500);
    expect((await app.inject({ url: `/test/agg/${mark}?q=${mark}` })).statusCode).toBe(500);
    expect(j.text()).not.toContain(mark);
    const errs = j.entries().filter((e) => e.level === 50);
    expect(errs).toHaveLength(2);
    for (const e of errs) {
      expect(e.msg).toBe("исключение");
      expect(Object.keys(e.err as object).sort()).toEqual(["name", "stack"]);
    }
    expect(errs.map((e) => (e.err as { name: string }).name)).toEqual(["Error", "AggregateError"]);
  });

  it("двойная отправка ответа (FST_ERR_REP_ALREADY_SENT) — код без адреса и без «Reply was already sent»", async () => {
    const j = logged();
    app = j.app;
    app.get("/test/twice/:secret", async (_req, reply) => {
      await reply.send("a");
      void reply.send("b");
      return reply;
    });
    expect((await app.inject({ url: `/test/twice/${mark}?q=${mark}` })).statusCode).toBe(200);
    expect(j.text()).not.toContain(mark);
    expect(j.text()).not.toContain("Reply was already sent");
    const warn = j.entries().find((e) => (e.err as { code?: string } | undefined)?.code === "FST_ERR_REP_ALREADY_SENT");
    expect(warn).toMatchObject({ level: 40, msg: "исключение", err: { name: "FastifyError", code: "FST_ERR_REP_ALREADY_SENT" } });
  });

  it("req.log и reply.log: исключение первым аргументом и { err } с сообщением err.message — без текста исключения", async () => {
    const j = logged();
    app = j.app;
    app.get("/test/own/:secret", async (req, reply) => {
      const { secret } = req.params as { secret: string };
      req.log.error(new Error(`первым ${secret}`));
      const e = new RangeError(`объект ${secret}`);
      reply.log.warn({ err: e, agent_code: "nspk:agent:x:v1" }, e.message);
      reply.log.warn({ err: new Error(secret) }, "своё сообщение");
      return { ok: true };
    });
    expect((await app.inject({ url: `/test/own/${mark}` })).statusCode).toBe(200);
    expect(j.text()).not.toContain(mark);
    const own = j.entries().filter((e) => e.err !== undefined);
    expect(own.map((e) => [e.level, e.msg, (e.err as { name: string }).name, e.agent_code])).toEqual([
      [50, "исключение", "Error", undefined],
      [40, "исключение", "RangeError", "nspk:agent:x:v1"],
      [40, "своё сообщение", "Error", undefined],
    ]);
    // Дочерний журнал запроса: перехват унаследован, привязка reqId сохранена.
    for (const e of own) expect(e.reqId).toBeDefined();
  });

  it("строки Fastify с адресом и сбой перехвата", () => {
    expect(pathlessLogArgs([`Reply was already sent, did you forget to "return reply" in the "/x/${mark}" (GET) route?`])).toEqual([
      { code: "FST_ERR_REP_ALREADY_SENT" },
      "ответ уже отправлен",
    ]);
    expect(pathlessLogArgs([`Route GET:/x/${mark}?q=${mark} not found`])).toEqual(["маршрут не найден"]);
    expect(pathlessLogArgs(["Server listening at http://127.0.0.1:3000"])).toEqual(["Server listening at http://127.0.0.1:3000"]);
    expect(pathlessLogArgs([{ agent_code: "a" }, "текст", 1])).toEqual([{ agent_code: "a" }, "текст", 1]);
  });

  it("перехват не бросает: сбой разбора аргументов — запись «запись журнала отклонена» без аргументов", async () => {
    const j = logged();
    app = j.app;
    const bad = {
      err: new Error(mark),
      get boom(): never {
        throw new Error(mark);
      },
    };
    expect(() => app?.log.error(bad, mark)).not.toThrow();
    expect(j.text()).not.toContain(mark);
    expect(j.entries().at(-1)).toMatchObject({ level: 50, msg: "запись журнала отклонена" });
  });

  it("свой logMethod в опциях получает уже очищенные аргументы", async () => {
    const seen: unknown[][] = [];
    const j = logged({
      hooks: {
        logMethod(this: unknown, args: unknown[], method: (...a: unknown[]) => void) {
          seen.push(args);
          method.apply(this, args);
        },
      },
    });
    app = j.app;
    app.log.error(new Error(mark));
    expect(JSON.stringify(seen)).not.toContain(mark);
    expect(j.text()).not.toContain(mark);
  });
});

describe("уровень журнала не ниже info (РП63 п. 13)", () => {
  const withLevel = (opts: Record<string, unknown>): FastifyInstance =>
    buildServer({ env: "dev", logger: { stream: { write: () => undefined }, ...opts } });

  it.each([["trace"], ["debug"], ["verbose"], [""], [10]])("уровень %j — отказ запуска", (level) => {
    expect(() => withLevel({ level })).toThrow(/запуск запрещён \(РП63 п\. 13\)/);
  });

  it("свои уровни (customLevels, useOnlyCustomLevels) — отказ запуска", () => {
    expect(() => withLevel({ level: "info", customLevels: { audit: 35 } })).toThrow(/РП63 п\. 13/);
    expect(() => withLevel({ level: "info", useOnlyCustomLevels: false })).toThrow(/РП63 п\. 13/);
  });

  it.each([["info"], ["warn"], ["error"], ["fatal"], ["silent"], [undefined]])("уровень %j — запуск", async (level) => {
    const app = withLevel(level === undefined ? {} : { level });
    expect(app.log.level).toBe(level ?? "info");
    await app.close();
  });

  it("logger: true — info; logger: false — журнала нет, проверки нет", async () => {
    const on = buildServer({ env: "dev", logger: true });
    expect(on.log.level).toBe("info");
    await on.close();
    const off = buildServer({ env: "dev", logger: false });
    await off.close();
  });

  it("страж: в src нет уровня маршрута (logLevel), присваивания .level и child(…, { level }) — проверка при старте их не видит", () => {
    const root = join(import.meta.dirname, "../../src");
    const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));
    expect(files.length).toBeGreaterThan(50);
    const found: string[] = [];
    for (const f of files) {
      const text = readFileSync(join(root, f), "utf8");
      for (const re of [/\blogLevel\b/, /\.level\s*=(?!=)/, /\.child\([^)]*\blevel\b/s]) if (re.test(text)) found.push(`${f}: ${String(re)}`);
    }
    expect(found).toEqual([]);
  });
});
