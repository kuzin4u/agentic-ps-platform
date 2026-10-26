// РП63 п. 12–13 (PS-05в ч. 1, решения владельца 26.10, PR #74): журнал без текста исключения и сырого адреса —
// перехват hooks.logMethod; уровень журнала не ниже info — отказ запуска; уровень маршрута и смена уровня в коде — страж.
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer, pathlessLogArgs } from "../../src/server.js";
import { errFields as errFieldsOf } from "../../src/pao/transport.js";

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

  it("бросили не Error — throw { message } и throw \"строка\" с путём: поле err любого типа очищается (КТ1 № 1)", async () => {
    const j = logged();
    app = j.app;
    app.get("/test/obj/:secret", async (req) => {
      const { secret } = req.params as { secret: string };
      throw { message: `нет /test/obj/${secret}`, statusCode: 500, detail: secret };
    });
    app.get("/test/str/:secret", async (req) => {
      const { secret } = req.params as { secret: string };
      throw `нет /test/str/${secret}`;
    });
    expect((await app.inject({ url: `/test/obj/${mark}` })).statusCode).toBe(500);
    expect((await app.inject({ url: `/test/str/${mark}` })).statusCode).toBe(500);
    expect(j.text()).not.toContain(mark);
    const errs = j.entries().filter((e) => e.level === 50);
    expect(errs.map((e) => [e.msg, e.err])).toEqual([
      ["исключение", { name: "object" }],
      ["исключение", { name: "string" }],
    ]);
  });

  it("уже очищенное поле err (errFields в коде маршрута) — как есть; запись без исключения — те же аргументы, без копии", () => {
    const clean = { name: "PgError", code: "57014", stack: "    at q (x.ts:1:1)" };
    expect(pathlessLogArgs([{ err: clean, agent_code: "a" }, "ПАО: сбой источника"])).toEqual([
      { err: clean, agent_code: "a" },
      "ПАО: сбой источника",
    ]);
    // С message — не очищенное: errFields от объекта.
    expect(pathlessLogArgs([{ err: { name: "E", message: mark } }])).toEqual([{ err: { name: "object" } }, "исключение"]);
    for (const args of [[{ agent_code: "a" }, "текст"], ["строка"], [42]] as unknown[][]) expect(pathlessLogArgs(args)).toBe(args);
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

  it("сообщение с текстом исключения подстрокой и аргументы подстановки при исключении (РП64 п. 9, КТ1 № 2)", () => {
    const e = new Error(`сбой /x/${mark}`);
    expect(pathlessLogArgs([{ err: e }, `не удалось: ${e.message}`])).toEqual([{ err: errFieldsOf(e) }, "исключение"]);
    // Подстановка %s с текстом исключения: аргументы отбрасываются, сообщение без них остаётся.
    expect(pathlessLogArgs([{ err: e }, "не удалось: %s", e.message, mark])).toEqual([{ err: errFieldsOf(e) }, "не удалось: %s"]);
    // Пустой текст исключения — не подстрока любого сообщения.
    const empty = new Error("");
    expect(pathlessLogArgs([{ err: empty }, "своё"])).toEqual([{ err: errFieldsOf(empty) }, "своё"]);
    // Строка, брошенная как исключение, — тоже текст.
    expect(pathlessLogArgs([{ err: `нет ${mark}` }, `ответ: нет ${mark}`])).toEqual([{ err: { name: "string" } }, "исключение"]);
  });

  it("исключение под другим именем поля первого уровня — errFields; глубже — граница (РП64 п. 9, КТ1 № 4)", async () => {
    const j = logged();
    app = j.app;
    app.get("/test/field/:secret", async (req) => {
      const { secret } = req.params as { secret: string };
      const e = new TypeError(`поле ${secret}`);
      req.log.warn({ error: e, agent_code: "nspk:agent:x:v1" }, e.message);
      req.log.warn({ error: e, cause: new Error(`второе ${secret}`) }, "своё сообщение %s", secret);
      return { ok: true };
    });
    expect((await app.inject({ url: `/test/field/${mark}` })).statusCode).toBe(200);
    expect(j.text()).not.toContain(mark);
    const own = j.entries().filter((e) => e.error !== undefined);
    expect(own.map((e) => [e.msg, (e.error as { name: string }).name, (e.cause as { name: string } | undefined)?.name])).toEqual([
      ["исключение", "TypeError", undefined],
      ["своё сообщение %s", "TypeError", "Error"],
    ]);
    // Копия — только при найденном исключении; вложенное глубже первого уровня — как есть (граница, держат стражи).
    const nested = [{ ctx: { err: new Error("x") } }, "текст"];
    expect(pathlessLogArgs(nested)).toBe(nested);
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
    // JSON.stringify(new Error()) — «{}»: проверка по строке прошла бы и без очистки (КТ1 № 7).
    expect(seen[0]?.[0]).not.toBeInstanceOf(Error);
    expect(seen[0]?.[1]).toBe("исключение");
    expect(j.text()).not.toContain(mark);
  });

  it("свой logMethod из опций бросает — перехват не бросает, запись «запись журнала отклонена» (КТ1 № 8)", () => {
    const j = logged({
      hooks: {
        logMethod() {
          throw new Error(mark);
        },
      },
    });
    app = j.app;
    expect(() => app?.log.warn({ agent_code: "a" }, "текст")).not.toThrow();
    expect(j.text()).not.toContain(mark);
    expect(j.entries().at(-1)).toMatchObject({ level: 40, msg: "запись журнала отклонена" });
  });
});

describe("уровень журнала не ниже info (РП63 п. 13)", () => {
  const withLevel = (opts: Record<string, unknown>): FastifyInstance =>
    buildServer({ env: "dev", logger: { stream: { write: () => undefined }, ...opts } });

  it.each([["trace"], ["debug"], ["verbose"], [""], [10]])("уровень %j — отказ запуска, причина — уровень", (level) => {
    expect(() => withLevel({ level })).toThrow(/^Журнал: уровень «.*» ниже info или не из стандартных pino — запуск запрещён \(РП63 п\. 13\)$/);
  });

  it("свои уровни и свой порядок — отказ запуска, причина названа отдельно (КТ1 № 5, 9)", () => {
    const only = (r: string) => new RegExp(`^Журнал: ${r} — запуск запрещён \\(РП63 п\\. 13\\)$`);
    expect(() => withLevel({ level: "info", customLevels: { audit: 35 } })).toThrow(only("заданы customLevels / useOnlyCustomLevels"));
    expect(() => withLevel({ level: "info", useOnlyCustomLevels: false })).toThrow(only("заданы customLevels / useOnlyCustomLevels"));
    // levelComparison: "DESC" при level: "info" включает trace и debug (pino 10.4.0, lib/levels.js).
    expect(() => withLevel({ level: "info", levelComparison: "DESC" })).toThrow(only("задан levelComparison"));
    expect(() => withLevel({ level: "info", levelComparison: () => true })).toThrow(only("задан levelComparison"));
    expect(() => withLevel({ level: "debug", levelComparison: "ASC" })).toThrow(
      only("уровень «debug» ниже info или не из стандартных pino; задан levelComparison"),
    );
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

  it("страж: в src уровень не меняется в коде — проверка при старте этого не видит (РП64 п. 9, КТ1 № 6)", () => {
    const found: string[] = [];
    for (const [f, text] of srcFiles()) {
      const res = [/\blogLevel\b/, /\.level\s*=(?!=)/, /\[\s*["'`]level["'`]\s*\]\s*=(?!=)/, /\bchildLoggerFactory\b/];
      // levelComparison — только в проверке уровня при старте (assertLogLevel).
      if (f !== "server.ts") res.push(/\blevelComparison\b/);
      for (const re of res) if (re.test(text)) found.push(`${f}: ${String(re)}`);
      for (const [call, args] of calls(text, /\.child\(|\bObject\.assign\(/g)) if (/\blevel\b/.test(args)) found.push(`${f}: ${call}${args}`);
    }
    expect(found).toEqual([]);
  });

  it("страж: аргументы вызовов журнала в src — без .message и без подстановок %s / %d / %o / %O / %j (РП64 п. 9, КТ1 № 2)", () => {
    const found: string[] = [];
    let n = 0;
    for (const [f, text] of srcFiles()) {
      for (const [call, args] of calls(text, LOG_CALL)) {
        n++;
        if (/\.message\b/.test(args) || /%[sdifjoO]/.test(args)) found.push(`${f}: ${call}${args.slice(0, 80)}`);
      }
    }
    // Поиск видит вызовы: req.log.warn, app.log[level], this.deps.log?.(…), log("warn", …).
    expect(n).toBeGreaterThan(150);
    expect(found).toEqual([]);
  });

  it("поиск вызовов стражей: скобки внутри аргументов, оба вида вызова журнала", () => {
    const text = 'x.child(bindings(), { level: "debug" }); req.log.warn({ a: f(1) }, e.message); deps.log?.("warn", {}, "%s")';
    expect([...calls(text, /\.child\(/g)].map(([, a]) => a)).toEqual(['bindings(), { level: "debug" }']);
    expect([...calls(text, LOG_CALL)].map(([c]) => c)).toEqual(["log.warn(", "log?.("]);
  });
});

/** Начало вызова журнала: log(…), log?.(…), log.warn(…), log[level](…), logger.info(…). */
const LOG_CALL = /\b(?:log|logger)(?:\?\.)?(?:\.(?:trace|debug|info|warn|error|fatal)|\[[^\]\n]+\])?(?:\?\.)?\(/g;

function srcFiles(): [string, string][] {
  const root = join(import.meta.dirname, "../../src");
  const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));
  expect(files.length).toBeGreaterThan(50);
  return files.map((f) => [f, readFileSync(join(root, f), "utf8")]);
}

/** Вызовы по началу start: текст начала и аргументы до парной скобки (скобки внутри аргументов учитываются). */
function* calls(text: string, start: RegExp): Generator<[string, string]> {
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
