// Эмулятор продавцов: форма API — К6 пула (GET /v1/shops, GET /v1/shops/{id}/catalog, POST /v1/shops/{id}/orders),
// плюс приём пакета агентской оплаты (POST /v1/shops/{id}/orders/{order_id}/payment, РП22 п. 5).
// Эмулятор, а не контракт Платформы: публичный контракт для агентов — только ПАО (инвариант 10).
// Сумму заказа считает продавец по своей цене; в авторизацию её переносит эквайрер (инвариант 5).
import { randomUUID } from "node:crypto";
import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import type { Acquirer } from "../acquirer/acquirer.js";
import { parsePaymentPackage, type PaymentPackage } from "../acquirer/package.js";
import { SHOPS, byShopId, catalogView, isOrderable, zoneOf, type Shop } from "./shops.js";
import type { MerchantAgentVerifier, MerchantAuthError } from "./verify.js";

/** Метаданные пакета для сверки при эквайрере без поддержки aoi (РП22 п. 6; API для продавцов — PS-30). */
export interface PackageMetadata {
  readonly merchant_id: string;
  readonly credential_ref: string;
  readonly order_ref: string;
  readonly aoi: PaymentPackage["aoi"];
}

export interface ReconciliationPort {
  submit(m: PackageMetadata): Promise<void>;
}

export interface MerchantsOptions {
  readonly verifier: MerchantAgentVerifier;
  readonly acquirer: Acquirer;
  /** Заглушка API для продавцов (PS-30): нужна, когда эквайрер не переносит aoi. */
  readonly reconciliation?: ReconciliationPort;
  readonly shops?: readonly Shop[];
  /** Лимит обращений к витринам с одного адреса в минуту — на все маршруты /v1 (стендовый параметр). */
  readonly rateLimitPerMin: number;
}

/** PAYING — оплата в процессе: ставится до первого обращения к эквайреру, повторная оплата невозможна. */
export const ORDER_STATUSES = ["CREATED", "PAYING", "PAID", "DECLINED", "REJECTED"] as const;
export type OrderStatus = (typeof ORDER_STATUSES)[number];

export interface OrderLine {
  readonly sku: string;
  readonly qty: number;
  readonly price: number;
}

export interface Order {
  readonly id: string;
  readonly shop_id: string;
  readonly merchant_id: string;
  readonly items: readonly OrderLine[];
  readonly total: number;
  readonly currency: string;
  /** Мандат корзины, по которому агент оформляет заказ; сверяется с cart_mandate_id пакета. */
  readonly cart_mandate_id: string;
  readonly agent_code: string;
  readonly status: OrderStatus;
  /**
   * Итог авторизации по ответу эквайрера — только «одобрено / отклонено». op_ref и код решения продавцу не раскрываются:
   * op_ref — результат сверки Платформы (РП22 п. 6), о решении агент узнаёт событием Платформы (РП2, инвариант 5).
   */
  readonly payment: { readonly approved: boolean } | null;
  /** Отказ продавца в исполнении после оплаты; оплата возвращена реверсалом (Д06). */
  readonly fulfilment_refused: boolean;
}

export type MerchantErrorCode =
  | "AGENT_UNIDENTIFIED"
  | MerchantAuthError
  | "SHOP_NOT_FOUND"
  | "ORDER_NOT_FOUND"
  | "ORDERS_NOT_ACCEPTED"
  | "ITEM_INVALID"
  | "ITEM_INCOMPLETE"
  | "PACKAGE_INVALID"
  | "PACKAGE_MISMATCH"
  | "ORDER_NOT_PAYABLE"
  | "UPSTREAM_UNAVAILABLE"
  | "RATE_LIMITED";

const HTTP: Record<MerchantErrorCode, number> = {
  AGENT_UNIDENTIFIED: 403,
  KEY_UNKNOWN: 401,
  AGENT_MISMATCH: 401,
  KEY_EXPIRED: 401,
  SIGNATURE_INVALID: 401,
  SHOP_NOT_FOUND: 404,
  ORDER_NOT_FOUND: 404,
  ORDERS_NOT_ACCEPTED: 409,
  ITEM_INVALID: 422,
  ITEM_INCOMPLETE: 422,
  PACKAGE_INVALID: 422,
  PACKAGE_MISMATCH: 409,
  ORDER_NOT_PAYABLE: 409,
  UPSTREAM_UNAVAILABLE: 503,
  RATE_LIMITED: 429,
};

const fail = (reply: FastifyReply, code: MerchantErrorCode): FastifyReply => reply.code(HTTP[code]).send({ code });

const shopView = (s: Shop) => ({
  id: s.id,
  merchant_id: s.merchant_id,
  name: s.name,
  category: s.category,
  zone: zoneOf(s),
  readiness_mark: s.readiness_mark,
});

const LIMIT_MAX = 100;
/** Метка превышения лимита частоты: errorResponseBuilder выбрасывает её, обработчик ошибок отвечает {code}. */
const RATE_LIMITED = Object.freeze({ statusCode: 429, code: "RATE_LIMITED" });
const SIGNATURE_HEADERS = ["signature", "signature-input", "x-agent-code"];

export function buildMerchantsServer(opts: MerchantsOptions): FastifyInstance {
  const root = Fastify({ logger: false });
  if (!Number.isSafeInteger(opts.rateLimitPerMin) || opts.rateLimitPerMin < 1) {
    throw new Error("rateLimitPerMin — целое ≥ 1");
  }
  // Лимит по адресу — до опознания агента и до чтения каталога ключей: неподписанный поток тоже ограничен.
  // Превышение — 429 RATE_LIMITED с Retry-After. Тот же механизм возьмёт шлюз ПАО (PS-05).
  void root.register(rateLimit, {
    global: true,
    max: opts.rateLimitPerMin,
    timeWindow: 60_000,
    keyGenerator: (req) => req.ip,
    errorResponseBuilder: () => RATE_LIMITED,
  });
  // Тело 429 — только {code}, как у остальных отказов витрины; Retry-After плагин ставит до выброса.
  root.setErrorHandler((err, _req, reply) => {
    if (err === RATE_LIMITED) return fail(reply, "RATE_LIMITED");
    return reply.send(err);
  });
  // Порядок выдачи — по id и не зависит от знака готовности (A5 п. 5.2, A6 п. 2.1).
  const shops = [...(opts.shops ?? SHOPS)].sort(byShopId);
  const byId = new Map(shops.map((s) => [s.id, s]));
  const orders = new Map<string, Order>();
  if (!opts.acquirer.aoiSupport && !opts.reconciliation) {
    throw new Error("Эквайрер без поддержки aoi: нужен порт сверки (РП22 п. 6)");
  }

  // Маршруты — в области после плагина лимита: его хук onRoute должен видеть каждый маршрут.
  void root.register(async (app) => {
    app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => done(null, body));

    /** Опознание: без заголовков подписи — человек (null); с ними — только проверенный агент, иначе отказ. */
    async function identify(req: FastifyRequest): Promise<{ agent: string | null } | { error: MerchantErrorCode }> {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue;
        if (typeof v !== "string") return { error: "SIGNATURE_INVALID" };
        headers[k.toLowerCase()] = v;
      }
      if (!SIGNATURE_HEADERS.some((h) => h in headers)) return { agent: null };
      const url = req.raw.url ?? "";
      const q = url.indexOf("?");
      let r;
      try {
        r = await opts.verifier.verify({
          method: req.method,
          path: q < 0 ? url : url.slice(0, q),
          query: q < 0 ? "" : url.slice(q + 1),
          headers,
          body: typeof req.body === "string" ? req.body : "",
        });
      } catch {
        // Каталог ключей недоступен — отказ, не догадка (инвариант 3).
        return { error: "UPSTREAM_UNAVAILABLE" };
      }
      return r.ok ? { agent: r.agent_code } : { error: r.code };
    }

    /** Подписанный агент обязателен: без подписи — AGENT_UNIDENTIFIED (A5 п. 2.1–2.2). */
    async function requireAgent(req: FastifyRequest, reply: FastifyReply): Promise<string | null> {
      const who = await identify(req);
      if ("error" in who) {
        void fail(reply, who.error);
        return null;
      }
      if (who.agent === null) {
        void fail(reply, "AGENT_UNIDENTIFIED");
        return null;
      }
      return who.agent;
    }

    const json = (req: FastifyRequest): unknown => {
      try {
        return typeof req.body === "string" ? JSON.parse(req.body) : undefined;
      } catch {
        return undefined;
      }
    };

    app.get("/v1/shops", async () => ({ shops: shops.map(shopView) }));

    app.get<{ Params: { id: string }; Querystring: { query?: string; limit?: string } }>(
      "/v1/shops/:id/catalog",
      async (req, reply) => {
        const shop = byId.get(req.params.id);
        if (!shop) return fail(reply, "SHOP_NOT_FOUND");
        const who = await identify(req);
        if ("error" in who) return fail(reply, who.error);
        // Опознанный агент из реестра обслуживается на общих условиях (A5 п. 2.2); неопознанным SHOP-4401 отказывает.
        if (shop.behaviour === "REJECTS_UNIDENTIFIED" && who.agent === null) return fail(reply, "AGENT_UNIDENTIFIED");
        const query = (req.query.query ?? "").toLowerCase();
        const limit = Math.min(Math.max(Number.parseInt(req.query.limit ?? "", 10) || LIMIT_MAX, 1), LIMIT_MAX);
        const items = shop.items
          .filter((i) => !query || [i.title, i.description, i.category].some((t) => t?.toLowerCase().includes(query)))
          .slice(0, limit)
          .map((i) => catalogView(i, who.agent !== null));
        return { shop: shopView(shop), items };
      },
    );

    app.post<{ Params: { id: string } }>("/v1/shops/:id/orders", async (req, reply) => {
      const shop = byId.get(req.params.id);
      if (!shop) return fail(reply, "SHOP_NOT_FOUND");
      // Эмулятор принимает заказы только от агентов: заказ человека — вне сценариев Платформы.
      const agent = await requireAgent(req, reply);
      if (!agent) return reply;
      if (shop.behaviour === "READ_ONLY") return fail(reply, "ORDERS_NOT_ACCEPTED");

      const body = json(req) as { items?: unknown; cart_mandate_id?: unknown } | undefined;
      const cart_mandate_id = body?.cart_mandate_id;
      const raw = body?.items;
      if (typeof cart_mandate_id !== "string" || cart_mandate_id === "" || !Array.isArray(raw) || raw.length === 0) {
        return fail(reply, "ITEM_INVALID");
      }
      const lines: OrderLine[] = [];
      let currency: string | undefined;
      for (const r of raw as unknown[]) {
        const { sku, qty } = (r ?? {}) as { sku?: unknown; qty?: unknown };
        const item = shop.items.find((i) => i.sku === sku);
        if (!item || typeof qty !== "number" || !Number.isSafeInteger(qty) || qty < 1 || qty > 99) {
          return fail(reply, "ITEM_INVALID");
        }
        if (!isOrderable(item)) return fail(reply, "ITEM_INCOMPLETE");
        if (currency !== undefined && currency !== item.currency) return fail(reply, "ITEM_INVALID");
        currency = item.currency;
        // Цена заказа — цена продавца для всех; total из запроса не читается (инвариант 5).
        lines.push({ sku: item.sku, qty, price: item.price });
      }
      const order: Order = {
        id: `ORD-${randomUUID().slice(0, 8)}`,
        shop_id: shop.id,
        merchant_id: shop.merchant_id,
        items: lines,
        total: lines.reduce((s, l) => s + l.price * l.qty, 0),
        currency: currency as string,
        cart_mandate_id,
        agent_code: agent,
        status: "CREATED",
        payment: null,
        fulfilment_refused: false,
      };
      orders.set(order.id, order);
      return reply.code(201).send(order);
    });

    app.post<{ Params: { id: string; order_id: string } }>(
      "/v1/shops/:id/orders/:order_id/payment",
      async (req, reply) => {
        const shop = byId.get(req.params.id);
        if (!shop) return fail(reply, "SHOP_NOT_FOUND");
        const agent = await requireAgent(req, reply);
        if (!agent) return reply;
        const order = orders.get(req.params.order_id);
        if (!order || order.shop_id !== shop.id || order.agent_code !== agent) return fail(reply, "ORDER_NOT_FOUND");
        if (order.status !== "CREATED") return fail(reply, "ORDER_NOT_PAYABLE");

        // aoi.mandate_id с мандатом корзины сверяет ADP (AOI_MISMATCH, ПИ §6), не продавец: источник истины — запись мандата.
        // Пакет подписан агентом: подпись обращения покрывает тело через content-digest (RFC 9421, РП22 п. 5).
        const pkg = parsePaymentPackage(json(req));
        if (!pkg) return fail(reply, "PACKAGE_INVALID");
        if (pkg.order_ref !== order.id || pkg.aoi.agent_code !== agent || pkg.cart_mandate_id !== order.cart_mandate_id) {
          return fail(reply, "PACKAGE_MISMATCH");
        }

        // Статус меняется до первого await: параллельная вторая оплата получит ORDER_NOT_PAYABLE, авторизация уйдёт одна.
        orders.set(order.id, { ...order, status: "PAYING" });
        if (!opts.acquirer.aoiSupport && opts.reconciliation) {
          // Метаданные — только для сверки и отчётности, решение ADP от них не зависит (РП22 п. 6):
          // сбой порта сверки авторизацию не останавливает, расхождение найдёт сверка.
          try {
            await opts.reconciliation.submit({
              merchant_id: shop.merchant_id,
              credential_ref: pkg.credential_ref,
              order_ref: order.id,
              aoi: structuredClone(pkg.aoi),
            });
          } catch (e) {
            req.log.error({ err: e }, "витрина: метаданные пакета для сверки не переданы");
          }
        }
        let auth;
        try {
          auth = await opts.acquirer.authorize({
            merchant: { id: shop.merchant_id, mcc: shop.mcc, name: shop.name },
            amount: order.total,
            currency: order.currency,
            order_ref: order.id,
            package: pkg,
          });
        } catch {
          // Авторизация не ушла — заказ снова можно оплатить.
          orders.set(order.id, order);
          return fail(reply, "UPSTREAM_UNAVAILABLE");
        }
        let next: Order = { ...order, payment: { approved: auth.approved }, status: auth.approved ? "PAID" : "DECLINED" };
        if (auth.approved && shop.behaviour === "REJECTS_FULFILMENT") {
          try {
            await opts.acquirer.reverse(auth.op_ref);
          } catch {
            orders.set(order.id, next);
            return fail(reply, "UPSTREAM_UNAVAILABLE");
          }
          next = { ...next, status: "REJECTED", fulfilment_refused: true };
        }
        orders.set(order.id, next);
        return next;
      },
    );
  });

  return root;
}
