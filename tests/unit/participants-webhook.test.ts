// П10 Вебхук-сигнал уведомлений клиента банку (PS-20 ч. 3 К3.7; РП46 (б) п. 3, доп. п. 9 (о4)): POST {notification_id, seq}
// на notify_url из записи доверенного участника, без подписи до SEC-1; проверка адреса и повтор — как push агенту (РП40):
// форма и список хостов, адреса имени перед каждой отправкой, без перенаправлений, исчерпание — уведомление только в ленте.
import { describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { createIssuerWebhookReceiver, STAND_ISSUER_NOTIFY_URL, STAND_ISSUER_WEBHOOK_HOST } from "../../src/env/issuer/webhook.js";
import type { EventTransport } from "../../src/pao/delivery.js";
import { MemoryParticipantNotificationStore, type NotificationDraft } from "../../src/participants/notifications.js";
import { WebhookDeliverer } from "../../src/participants/webhook.js";
import { createStand } from "../../src/stand/index.js";
import { createStandDns } from "../../src/stand/dns.js";

const T = Date.parse("2026-10-20T10:00:00Z");
const BANK = "stand:issuer-emulator";
const PARAMS = { event_retry_max: 3, event_delivery_timeout_ms: 5_000, participant_notify_allow_hosts: [STAND_ISSUER_WEBHOOK_HOST] };
const draft = (op_ref: string): NotificationDraft => ({ type: "client.limit_declined", key: op_ref, data: { principal_ref: "prn_7f3c9a", op_ref } });

function setup(opts: { url?: string | undefined; urlThrows?: boolean } = {}) {
  let now = T;
  const store = new MemoryParticipantNotificationStore(new MemoryOperationStore());
  const dns = createStandDns();
  const receiver = createIssuerWebhookReceiver();
  const logs: Record<string, unknown>[] = [];
  const url = "url" in opts ? opts.url : STAND_ISSUER_NOTIFY_URL;
  const deliverer = new WebhookDeliverer({
    store,
    notifyUrl: () => {
      if (opts.urlThrows) throw new Error("реестр участников недоступен");
      return url;
    },
    resolveHost: dns.resolve,
    transport: receiver.transport,
    params: PARAMS,
    now: () => now,
    stand: true,
    log: (_l, f) => logs.push(f),
  });
  store.insertNow(BANK, [draft("op-1")], new Date(T).toISOString());
  const id = async () => (await store.page(BANK, undefined, 1))[0]!.notification_id;
  return { store, dns, receiver, deliverer, logs, id, advance: (ms: number) => (now += ms) };
}

describe("вебхук-сигнал уведомлений банку (РП46 (б) п. 3)", () => {
  it("доставка: POST {notification_id, seq} на notify_url, заголовок x-notification-id; DELIVERED", async () => {
    const { deliverer, receiver, store, id } = setup();
    expect(await deliverer.runOnce()).toBe(1);
    const nid = await id();
    expect(receiver.received).toEqual([{ url: STAND_ISSUER_NOTIFY_URL, notification_id: nid, seq: 1, header_notification_id: nid, status: 200 }]);
    expect(await store.delivery(nid)).toMatchObject({ state: "DELIVERED", attempts: 1 });
    expect(await deliverer.runOnce(), "доставленный сигнал отправлен ещё раз").toBe(0);
  });

  it("неуспешный ответ — повтор по nextAttemptDelayMs ядра; 500, 500, затем 200 — DELIVERED с третьей попытки", async () => {
    const { deliverer, receiver, store, id, advance } = setup();
    receiver.respond(500, 500);
    await deliverer.runOnce();
    const nid = await id();
    expect(await store.delivery(nid)).toMatchObject({ state: "PENDING", attempts: 1, last_reason: "http_500" });
    expect(await deliverer.runOnce(), "повтор раньше срока").toBe(0);
    for (let i = 0; i < 2; i++) {
      advance(60_000);
      await deliverer.runOnce();
    }
    expect(receiver.received.map((r) => r.status)).toEqual([500, 500, 200]);
    expect(await store.delivery(nid)).toMatchObject({ state: "DELIVERED", attempts: 3 });
  });

  it("исчерпание event_retry_max — EXHAUSTED, уведомление только в ленте; перенаправление — неуспешная попытка", async () => {
    const { deliverer, receiver, store, id, advance, logs } = setup();
    receiver.respond(302, 500, 500);
    for (let i = 0; i < 3; i++) {
      await deliverer.runOnce();
      advance(600_000);
    }
    expect(receiver.received.map((r) => r.status)).toEqual([302, 500, 500]);
    expect(await store.delivery(await id())).toMatchObject({ state: "EXHAUSTED", attempts: 3, last_reason: "http_500" });
    expect(logs.map((f) => f.reason)).toEqual(["redirect", "http_500", "http_500"]);
    expect((await store.page(BANK, undefined, 10)).length, "уведомление пропало из ленты").toBe(1);
  });

  it("адрес имени не глобальный (подмена DNS после записи) — без соединения, неуспешная попытка address_not_global", async () => {
    const { deliverer, receiver, store, id, dns } = setup();
    dns.set(STAND_ISSUER_WEBHOOK_HOST, ["10.0.0.7"]);
    await deliverer.runOnce();
    expect(receiver.received, "соединение с внутренним адресом").toEqual([]);
    expect(await store.delivery(await id())).toMatchObject({ state: "PENDING", last_reason: "address_not_global" });
  });

  it("хост не из participant_notify_allow_hosts, не https, IP-литерал — без соединения", async () => {
    for (const [url, reason] of [
      ["https://bank.example/notify", "host_not_allowed"],
      ["http://issuer-emulator.stand/notify", "scheme"],
      ["https://10.0.0.7/notify", "ip_literal"],
    ] as const) {
      const { deliverer, receiver, store, id } = setup({ url });
      await deliverer.runOnce();
      expect(receiver.received, url).toEqual([]);
      expect(await store.delivery(await id()), url).toMatchObject({ state: "PENDING", last_reason: reason });
    }
  });

  it("вебхука в соглашении нет — SKIPPED без попытки; запись участника не прочитана — попытка отложена и не потрачена", async () => {
    const none = setup({ url: undefined });
    await none.deliverer.runOnce();
    expect(await none.store.delivery(await none.id())).toMatchObject({ state: "SKIPPED", attempts: 0, last_reason: "no_webhook" });
    const down = setup({ urlThrows: true });
    await down.deliverer.runOnce();
    expect(await down.store.delivery(await down.id())).toMatchObject({ state: "PENDING", attempts: 0, last_reason: "status_unavailable" });
  });

  it("стендовый транспорт или разрешение имени в рабочем сервере — отказ запуска (РП40 п. 8)", () => {
    const store = new MemoryParticipantNotificationStore(new MemoryOperationStore());
    const plain: EventTransport = async () => 200;
    expect(
      () => new WebhookDeliverer({ store, notifyUrl: () => undefined, resolveHost: createStandDns().resolve, transport: plain, params: PARAMS }),
    ).toThrow(/стендовый порт/);
    expect(
      () => new WebhookDeliverer({ store, notifyUrl: () => undefined, resolveHost: async () => [], transport: createIssuerWebhookReceiver().transport, params: PARAMS }),
    ).toThrow(/стендовый порт/);
  });

  it("стенд: revoke-all → client.revoked_all в ленте и сигнал банку стенда; повтор того же revocation_ref — без второго сигнала", async () => {
    const stand = createStand();
    stand.setClock(new Date(T));
    try {
      expect((await stand.issuer.revokeAll("prn_7f3c9a", "rev-all-hook")).statusCode).toBe(200);
      expect((await stand.issuer.revokeAll("prn_7f3c9a", "rev-all-hook")).statusCode).toBe(200);
      const feed = (await stand.issuer.getNotifications()).body as { notifications: { notification_id: string; seq: number; type: string }[] };
      expect(feed.notifications.map((n) => [n.seq, n.type])).toEqual([[1, "client.revoked_all"]]);
      expect(await stand.deliverParticipantNotifications()).toBe(1);
      expect(stand.issuerWebhook.handled).toEqual([feed.notifications[0]!.notification_id]);
      expect(await stand.notificationDelivery(feed.notifications[0]!.notification_id)).toMatchObject({ state: "DELIVERED" });
    } finally {
      await stand.close();
    }
  });
});
