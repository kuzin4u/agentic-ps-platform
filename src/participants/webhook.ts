// П10 Вебхук-сигнал уведомлений клиента банку (PS-20 ч. 3 К3.7; РП46 (б) п. 3, доп. п. 9 (о4)): POST {notification_id, seq}
// на notify_url из записи доверенного участника. Сигнал, а не содержание: без подписи Платформы до SEC-1 (как события
// агенту до ПАО 1.5.0, РП39 п. 6), содержание банк берёт из ленты GET /participants/v1/notifications. Проверка адреса и
// повтор — как push агенту (РП40 п. 2–7): форма и список хостов, адреса имени — заново перед каждой отправкой, соединение
// с проверенным IP, без перенаправлений, аренда попытки и номер взятия.
import { nextAttemptDelayMs } from "@kuzin4u/agentic-core";
import { DELIVERY_BATCH, DELIVERY_LEASE_MARGIN_MS, type DeliveryOutcome, type EventTransport } from "../pao/delivery.js";
import { checkSubscriptionUrl, resolveGlobal, STAND_PORT, withTimeout, type HostResolver } from "../pao/subscription.js";
import type { Params } from "../shared/config.js";
import type { DueNotice, ParticipantNotificationStore, StoredNotification } from "./notifications.js";

export interface WebhookDelivererDeps {
  readonly store: Pick<ParticipantNotificationStore, "claimDue" | "finishDelivery">;
  /** Адрес вебхука из записи участника на момент отправки; исключение — запись не прочитана (попытка не тратится). */
  readonly notifyUrl: (participant_code: string) => string | undefined;
  readonly resolveHost: HostResolver;
  readonly transport: EventTransport;
  readonly params: Pick<Params, "event_retry_max" | "event_delivery_timeout_ms" | "participant_notify_allow_hosts">;
  readonly now?: () => number;
  /** Стенд: только он принимает стендовые порты (РП40 п. 8). */
  readonly stand?: boolean;
  readonly log?: (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;
}

export class WebhookDeliverer {
  private readonly now: () => number;

  constructor(private readonly deps: WebhookDelivererDeps) {
    const standPort = STAND_PORT in deps.resolveHost || STAND_PORT in deps.transport;
    if (standPort && deps.stand !== true) {
      throw new Error("П10: стендовый порт вебхука в рабочем сервере — отказ запуска (РП40 п. 8)");
    }
    this.now = deps.now ?? (() => Date.now());
  }

  /** Один проход: до DELIVERY_BATCH попыток, строки — по одной, аренда — от взятия этой строки (как РП40 доп. п. 7). */
  async runOnce(): Promise<number> {
    let n = 0;
    for (; n < DELIVERY_BATCH; n++) {
      const t = this.now();
      const lease = t + this.deps.params.event_delivery_timeout_ms + DELIVERY_LEASE_MARGIN_MS;
      const [d] = await this.deps.store.claimDue(t, lease, 1);
      if (!d) break;
      const outcome = await this.attempt(d);
      await this.deps.store.finishDelivery(d.notification.notification_id, d.claim, outcome);
    }
    return n;
  }

  private async attempt(d: DueNotice): Promise<DeliveryOutcome> {
    const { notification: n, attempts } = d;
    const fields = { participant_code: n.participant_code, notification_id: n.notification_id, attempt: attempts };
    if (attempts > this.deps.params.event_retry_max) {
      this.deps.log?.("warn", { ...fields, reason: "lease_expired" }, "П10: вебхук исчерпан — уведомление только в ленте");
      return { state: "EXHAUSTED", reason: "lease_expired" };
    }
    let url: string | undefined;
    try {
      url = this.deps.notifyUrl(n.participant_code);
    } catch {
      this.deps.log?.("warn", { ...fields, reason: "status_unavailable" }, "П10: запись участника не прочитана — попытка отложена");
      return { state: "PENDING", next_at_ms: this.now() + nextAttemptDelayMs(d.claim), reason: "status_unavailable", refund: true };
    }
    // Вебхука в соглашении нет — уведомление только в ленте.
    if (url === undefined) return { state: "SKIPPED", reason: "no_webhook" };
    const form = checkSubscriptionUrl(url, this.deps.params.participant_notify_allow_hosts);
    if (!form.ok) return this.failed(n, attempts, form.reason, form.host);
    const timeout = this.deps.params.event_delivery_timeout_ms;
    const deadline = performance.now() + timeout;
    const addrs = await resolveGlobal(form.host, withTimeout(this.deps.resolveHost, timeout));
    if (!addrs.ok) return this.failed(n, attempts, addrs.reason, form.host);
    const left = Math.floor(deadline - performance.now());
    if (left < 1) return this.failed(n, attempts, "timeout", form.host);
    // Только номер и id: содержание — из ленты с подписью запроса участника (РП46 (б) п. 3).
    const body = JSON.stringify({ notification_id: n.notification_id, seq: n.seq });
    const headers = { "content-type": "application/json", "x-notification-id": n.notification_id };
    let status: number;
    try {
      status = await this.deps.transport({ url: form.url, host: form.host, address: addrs.addresses[0] as string }, body, headers, left);
    } catch {
      return this.failed(n, attempts, "transport_error", form.host);
    }
    if (status >= 200 && status < 300) return { state: "DELIVERED" };
    return this.failed(n, attempts, status >= 300 && status < 400 ? "redirect" : `http_${status}`, form.host);
  }

  /** Неуспешная попытка: повтор по nextAttemptDelayMs ядра или исчерпание (event_retry_max попыток всего). */
  private failed(n: StoredNotification, attempts: number, reason: string, host: string | undefined): DeliveryOutcome {
    const fields = { participant_code: n.participant_code, notification_id: n.notification_id, attempt: attempts, reason, host };
    if (attempts >= this.deps.params.event_retry_max) {
      this.deps.log?.("warn", fields, "П10: вебхук исчерпан — уведомление только в ленте");
      return { state: "EXHAUSTED", reason };
    }
    this.deps.log?.("info", fields, "П10: вебхук не доставлен — повтор");
    return { state: "PENDING", next_at_ms: this.now() + nextAttemptDelayMs(attempts), reason };
  }
}
