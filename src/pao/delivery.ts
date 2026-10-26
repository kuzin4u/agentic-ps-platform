// П9 Push-доставка событий агенту с повтором (РП40 п. 4–7, PS-08 К1.3в). Попытки — pao_event_deliveries (sql/102),
// событие — из ленты pao_events. Перед каждой отправкой заново: статус агента, подписка, форма адреса и адреса имени;
// соединение — с проверенным IP (SNI и Host — имя), без перенаправлений, тело ответа не читается. Подписи нет до ПАО 1.5.0.
import { request } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { nextAttemptDelayMs } from "@kuzin4u/agentic-core";
import type { AgentRecord, AgentSubscription } from "../registry/model.js";
import type { Params } from "../shared/config.js";
import { pushAllowed, toPaoEvent, type StoredEvent } from "./events.js";
import { checkSubscriptionUrl, resolveGlobal, STAND_PORT, withTimeout, type HostResolver } from "./subscription.js";

export type DeliveryState = "PENDING" | "DELIVERED" | "EXHAUSTED" | "SKIPPED";

/** Строка попытки, взятая обработчиком: attempts уже включает эту попытку; claim — номер взятия (только растёт). */
export interface DueDelivery {
  readonly event: StoredEvent;
  readonly attempts: number;
  readonly claim: number;
}

/** Итог попытки. `refund` — попытка не потрачена (агент не ACTIVE, статус не прочитан): attempts − 1. */
export type DeliveryOutcome =
  | { readonly state: "DELIVERED" }
  | { readonly state: "EXHAUSTED"; readonly reason: string }
  | { readonly state: "SKIPPED"; readonly reason: string }
  | { readonly state: "PENDING"; readonly next_at_ms: number; readonly reason: string; readonly refund?: boolean };

export interface DeliveryRow {
  readonly event_id: string;
  readonly agent_code: string;
  readonly state: DeliveryState;
  readonly attempts: number;
  readonly claims: number;
  readonly next_at_ms: number;
  readonly last_reason: string | null;
}

/** Хранилище попыток — то же, что лента (строка попытки пишется в транзакции события). */
export interface EventDeliveryStore {
  /**
   * Взять готовые строки PENDING (next_at_ms ≤ now): attempts + 1, claims + 1, next_at_ms — конец аренды попытки, чтобы
   * другой экземпляр не взял ту же строку, пока идёт отправка; упавший обработчик — повтор после аренды (РП40 п. 5).
   */
  claimDue(nowMs: number, leaseUntilMs: number, limit: number): Promise<readonly DueDelivery[]>;
  /** Итог попытки при совпадении номера взятия и PENDING; иначе ничего (строку уже взял другой после аренды). */
  finish(event_id: string, claim: number, outcome: DeliveryOutcome): Promise<void>;
  /** Строка попытки по событию — для тестов и разбора. */
  delivery(event_id: string): Promise<DeliveryRow | undefined>;
}

/** Куда и с каким IP соединяться: адрес уже проверен (РП40 п. 4). */
export interface DeliveryTarget {
  readonly url: string;
  readonly host: string;
  readonly address: string;
}

/** Транспорт: статус ответа; сбой соединения или тайм-аут — исключение. На стенде подменяется (РП40 п. 8). */
export type EventTransport = (
  target: DeliveryTarget,
  body: string,
  headers: Readonly<Record<string, string>>,
  timeoutMs: number,
) => Promise<number>;

/** Разрешение имени соединения — только проверенный адрес: подмена DNS между проверкой и соединением не срабатывает. */
export function pinnedLookup(address: string): LookupFunction {
  const family = isIP(address);
  return (_host, opts, cb) => {
    if (opts.all) cb(null, [{ address, family }]);
    else cb(null, address, family);
  };
}

/**
 * HTTPS-транспорт: соединение с проверенным IP, SNI и сертификат — по имени (имя в URL), перенаправления не выполняются
 * (node:https их не выполняет), тело ответа не читается — соединение закрывается после статуса. Тайм-аут — вся попытка.
 */
export const httpsTransport: EventTransport = (target, body, headers, timeoutMs) =>
  new Promise((ok, fail) => {
    const req = request(target.url, {
      method: "POST",
      headers: { ...headers, "content-length": String(Buffer.byteLength(body)) },
      lookup: pinnedLookup(target.address),
      agent: false,
    });
    const timer = setTimeout(() => req.destroy(new Error("тайм-аут доставки")), timeoutMs);
    req.on("response", (res) => {
      clearTimeout(timer);
      ok(res.statusCode ?? 0);
      res.destroy();
      req.destroy();
    });
    req.on("error", (err) => {
      clearTimeout(timer);
      fail(err);
    });
    req.end(body);
  });

export interface EventDelivererDeps {
  readonly store: EventDeliveryStore;
  /** Запись агента из реестра: статус — перед каждой отправкой (РП40 п. 6). Отклонённое обещание — статус не прочитан. */
  readonly agent: (agent_code: string) => Promise<AgentRecord | undefined>;
  readonly subscription: (agent_code: string) => Promise<AgentSubscription | undefined>;
  readonly resolveHost: HostResolver;
  readonly transport: EventTransport;
  readonly params: Pick<Params, "event_retry_max" | "event_delivery_timeout_ms" | "event_subscription_allow_hosts">;
  readonly now?: () => number;
  /** Стенд: только он принимает стендовые порты (РП40 п. 8). */
  readonly stand?: boolean;
  readonly log?: (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;
}

/** Запас аренды попытки сверх тайм-аута: разрешение имени и запись итога. */
export const DELIVERY_LEASE_MARGIN_MS = 5_000;

/** Сколько попыток обработчик делает за проход; строки берутся по одной — аренда у каждой своя. */
export const DELIVERY_BATCH = 20;

export class EventDeliverer {
  private readonly now: () => number;

  constructor(private readonly deps: EventDelivererDeps) {
    const standPort = STAND_PORT in deps.resolveHost || STAND_PORT in deps.transport;
    if (standPort && deps.stand !== true) {
      throw new Error("ПАО: стендовый порт доставки в рабочем сервере — отказ запуска (РП40 п. 8)");
    }
    this.now = deps.now ?? (() => Date.now());
  }

  /**
   * Один проход: до DELIVERY_BATCH попыток, строки — по одной: аренда (тайм-аут попытки + запас) отсчитывается от взятия
   * этой строки, и пока идёт её попытка, остальные строки свободны для других экземпляров. Число попыток.
   */
  async runOnce(): Promise<number> {
    let n = 0;
    for (; n < DELIVERY_BATCH; n++) {
      const t = this.now();
      const lease = t + this.deps.params.event_delivery_timeout_ms + DELIVERY_LEASE_MARGIN_MS;
      const [d] = await this.deps.store.claimDue(t, lease, 1);
      if (!d) break;
      const outcome = await this.attempt(d);
      await this.deps.store.finish(d.event.event_id, d.claim, outcome);
    }
    return n;
  }

  private async attempt(d: DueDelivery): Promise<DeliveryOutcome> {
    const { event, attempts } = d;
    const code = event.agent_code;
    const fields = { agent_code: code, event_id: event.event_id, attempt: attempts };
    // Строку взяли снова после аренды, а последняя засчитанная попытка уже ушла: отправок не больше event_retry_max
    // (дополнение РП40 п. 15).
    if (attempts > this.deps.params.event_retry_max) {
      this.deps.log?.("warn", { ...fields, reason: "lease_expired" }, "ПАО: доставка события исчерпана — событие только в ленте");
      return { state: "EXHAUSTED", reason: "lease_expired" };
    }
    let agent: AgentRecord | undefined;
    let sub: AgentSubscription | undefined;
    try {
      agent = await this.deps.agent(code);
      sub = await this.deps.subscription(code);
    } catch {
      // Статус не прочитан — не отправлять и не тратить попытку (инвариант 3); срок — от номера взятия: при долгом сбое
      // реестра строка берётся всё реже (дополнение РП40 п. 16).
      this.deps.log?.("warn", { ...fields, reason: "status_unavailable" }, "ПАО: статус агента не прочитан — попытка отложена");
      return { state: "PENDING", next_at_ms: this.now() + nextAttemptDelayMs(d.claim), reason: "status_unavailable", refund: true };
    }
    // Приостановлен или исключён — push не выполняется и не догоняет: событие в ленте (РП40 п. 6–7). Исключение —
    // agent.suspended приостановленному (РП54 п. 9).
    if (!agent || !pushAllowed(agent.status, event.type)) return this.skip(event, "agent_not_active");
    if (!sub || !sub.events.includes(event.type)) return this.skip(event, "not_subscribed");
    const form = checkSubscriptionUrl(sub.url, this.deps.params.event_subscription_allow_hosts);
    if (!form.ok) return this.failed(event, attempts, form.reason, form.host);
    // Один предел на всю попытку (РП40 п. 4): разрешение имени и отправка вместе не дольше event_delivery_timeout_ms.
    const timeout = this.deps.params.event_delivery_timeout_ms;
    const deadline = performance.now() + timeout;
    const addrs = await resolveGlobal(form.host, withTimeout(this.deps.resolveHost, timeout));
    if (!addrs.ok) return this.failed(event, attempts, addrs.reason, form.host);
    const left = Math.floor(deadline - performance.now());
    if (left < 1) return this.failed(event, attempts, "timeout", form.host);
    const body = JSON.stringify(toPaoEvent(event));
    const headers = { "content-type": "application/json", "x-event-id": event.event_id };
    let status: number;
    try {
      status = await this.deps.transport(
        { url: form.url, host: form.host, address: addrs.addresses[0] as string },
        body,
        headers,
        left,
      );
    } catch {
      return this.failed(event, attempts, "transport_error", form.host);
    }
    if (status >= 200 && status < 300) return { state: "DELIVERED" };
    // 3xx — не выполняется (РП40 п. 4), как и прочие ответы — неуспешная попытка.
    return this.failed(event, attempts, status >= 300 && status < 400 ? "redirect" : `http_${status}`, form.host);
  }

  private skip(event: StoredEvent, reason: string): DeliveryOutcome {
    this.deps.log?.("info", { agent_code: event.agent_code, event_id: event.event_id, reason }, "ПАО: push не выполняется — событие в ленте");
    return { state: "SKIPPED", reason };
  }

  /** Неуспешная попытка: повтор по nextAttemptDelayMs ядра или исчерпание (event_retry_max попыток всего). */
  private failed(event: StoredEvent, attempts: number, reason: string, host: string | undefined): DeliveryOutcome {
    const fields = { agent_code: event.agent_code, event_id: event.event_id, attempt: attempts, reason, host };
    if (attempts >= this.deps.params.event_retry_max) {
      this.deps.log?.("warn", fields, "ПАО: доставка события исчерпана — событие только в ленте");
      return { state: "EXHAUSTED", reason };
    }
    this.deps.log?.("info", fields, "ПАО: доставка события не удалась — повтор");
    return { state: "PENDING", next_at_ms: this.now() + nextAttemptDelayMs(attempts), reason };
  }
}

/**
 * Обработчик раз в everyMs (как очистка nonce, РП30 п. 4): сбой прохода — в журнал процесса. Таймер не держит процесс;
 * stop() снимает таймер и дожидается идущего прохода. Проходы не накладываются.
 */
export function startEventDelivery(
  deliverer: { runOnce(): Promise<unknown> },
  everyMs: number,
  onError: (err: unknown) => void,
): () => Promise<void> {
  let running: Promise<void> | undefined;
  const timer = setInterval(() => {
    if (running) return;
    running = deliverer
      .runOnce()
      .then(
        () => undefined,
        (err: unknown) => onError(err),
      )
      .finally(() => (running = undefined));
  }, everyMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await running;
  };
}
