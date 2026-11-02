// Журнал запросов без значений пути и текста исключений (РП61 п. 1–3, РП62 доп. 2, РП63 п. 12–13, РП64 п. 9): общий для
// сервера Платформы (`src/server.ts`) и экранов человека (`src/ui/`). Вынесен из `server.ts` без изменения поведения
// (UI-К2 ч. 1, решение владельца 02.11): экран не тянет за собой сервер Платформы.
import type { FastifyRequest, FastifyServerOptions } from "fastify";
import { errFields } from "../pao/transport.js";

/**
 * Запись о запросе (РП61 п. 1): метод и шаблон маршрута вместо url — значений параметров пути и строки запроса нет.
 * Маршрут не найден или шаблона нет — без route. Не бросает: исключение сериализатора сорвало бы запись и сам запрос.
 */
export function requestLogFields(req: FastifyRequest): Record<string, unknown> {
  // Защитно: шаблон — в своём try, чтобы сбой его чтения не терял адрес (у запроса frameworkErrors, РП62 п. 1, — контекст
  // события маршрутизатора без url).
  let route: unknown;
  try {
    route = req.is404 ? undefined : req.routeOptions?.url;
  } catch {
    route = undefined;
  }
  try {
    return {
      method: req.method,
      ...(typeof route === "string" ? { route } : {}),
      host: req.host,
      remoteAddress: req.ip,
      remotePort: req.socket?.remotePort,
    };
  } catch {
    return { method: req.method };
  }
}

/**
 * Аргументы записи журнала без текста исключения и сырого адреса (РП63 п. 12): исключение — только имя, код и кадры стека
 * (errFields, РП62 доп. 2), в том числе первым аргументом (log.error(err)); поле err любого типа (КТ1 № 1: throw { message }
 * и throw "строка" Fastify пишет как err, pino — с message) и исключение в любом другом поле первого уровня ({ error: e },
 * РП64 п. 9); сообщение, равное тексту исключения или содержащее его (defaultErrorLog, writeHeadError, `не удалось:
 * ${err.message}`), или без сообщения — «исключение»; аргументы подстановки при исключении отбрасываются; строки Fastify с
 * адресом — без него. Остальное — те же аргументы, без копии: перехват — на каждой записи (КТ1, горячий путь). Исключение
 * глубже первого уровня не обрабатывается — граница РП64 п. 9, держат стражи.
 */
export function pathlessLogArgs(args: readonly unknown[]): readonly unknown[] {
  const first = args[0];
  if (typeof first === "string") {
    // reply.js: «Reply was already sent, did you forget to "return reply" in the "<url>" (<method>) route?»
    if (first.startsWith("Reply was already sent")) return [{ code: "FST_ERR_REP_ALREADY_SENT" }, "ответ уже отправлен"];
    // LogController.routeNotFound по умолчанию: «Route <method>:<url> not found» (у сервера — PathlessLogController).
    if (first.startsWith("Route ") && first.endsWith(" not found")) return ["маршрут не найден"];
    return args;
  }
  if (first === null || typeof first !== "object") return args;
  if (first instanceof Error) return [{ err: errFields(first) }, "исключение"];
  let fields: Record<string, unknown> | undefined;
  const texts: string[] = [];
  for (const key of Object.keys(first)) {
    const v: unknown = (first as Record<string, unknown>)[key];
    // Уже очищенное err (errFields в коде маршрута) — как есть: errFields от объекта дал бы { name: "object" }.
    if (key === "err" ? isErrFields(v) : !(v instanceof Error)) continue;
    fields ??= { ...first };
    fields[key] = errFields(v);
    const text = v !== null && typeof v === "object" ? (v as { message?: unknown }).message : v;
    if (typeof text === "string" && text !== "") texts.push(text);
  }
  if (!fields && !("err" in first)) return args;
  // Без сообщения pino взял бы err.message; поле err — уже не исключение, поэтому сообщение задаётся явно.
  const msg = args[1];
  const out = fields ?? first;
  return typeof msg === "string" && !texts.some((t) => msg.includes(t)) ? [out, msg] : [out, "исключение"];
}

const ERR_FIELDS = new Set(["name", "code", "stack"]);

/** Результат errFields: только name, code и stack строками — message нет. */
function isErrFields(v: unknown): boolean {
  if (v === null || typeof v !== "object" || v instanceof Error) return false;
  return Object.entries(v).every(([k, x]) => ERR_FIELDS.has(k) && typeof x === "string");
}

/** Стандартные уровни pino не ниже info (РП63 п. 13): у trace и debug — rawPacket и reply.log.debug(err) с сырым путём. */
const LOG_LEVELS_ALLOWED = ["info", "warn", "error", "fatal", "silent"] as const;

/**
 * Уровень журнала (РП63 п. 13; решение владельца 26.10, PR #74): ниже info, не из стандартных pino, свои уровни
 * (customLevels) или свой порядок (levelComparison: "DESC" включает trace и debug при level: "info", КТ1 № 5) — отказ запуска
 * во всех средах, а не молчаливый info; причины — одним сообщением. Не задан — info Fastify.
 */
function assertLogLevel(base: Exclude<FastifyServerOptions["logger"], boolean | undefined>): void {
  const opts = base as { level?: unknown; customLevels?: unknown; useOnlyCustomLevels?: unknown; levelComparison?: unknown };
  const level = opts.level ?? "info";
  const reasons: string[] = [];
  if (!(LOG_LEVELS_ALLOWED as readonly unknown[]).includes(level)) reasons.push(`уровень «${String(level)}» ниже info или не из стандартных pino`);
  if (opts.customLevels !== undefined || opts.useOnlyCustomLevels !== undefined) reasons.push("заданы customLevels / useOnlyCustomLevels");
  if (opts.levelComparison !== undefined) reasons.push("задан levelComparison");
  if (reasons.length > 0) throw new Error(`Журнал: ${reasons.join("; ")} — запуск запрещён (РП63 п. 13)`);
}

const LOG_REJECTED = ["запись журнала отклонена"] as const;

/**
 * Опции журнала (РП61 п. 3, РП63 п. 12–13): сериализатор req, перехват записей logMethod, уровень не ниже info.
 * true — журнал Fastify по умолчанию, false — журнала нет. Перехват наследуют дочерние журналы (req.log, reply.log).
 */
export function withRequestSerializer(logger: FastifyServerOptions["logger"]): FastifyServerOptions["logger"] {
  if (!logger) return false;
  const base = logger === true ? {} : logger;
  assertLogLevel(base);
  const own = base.hooks?.logMethod;
  return {
    ...base,
    serializers: { ...base.serializers, req: requestLogFields },
    hooks: {
      ...base.hooks,
      logMethod(args, method, level) {
        let safe: readonly unknown[];
        // Перехват не бросает (как сериализатор): сбой — запись без аргументов; и у своего logMethod из опций (КТ1 № 8).
        try {
          safe = pathlessLogArgs(args);
        } catch {
          safe = LOG_REJECTED;
        }
        const call = safe as Parameters<typeof method>;
        if (!own) {
          method.apply(this, call);
          return;
        }
        try {
          own.call(this, call, method, level);
        } catch {
          method.apply(this, LOG_REJECTED as unknown as Parameters<typeof method>);
        }
      },
    },
  };
}
