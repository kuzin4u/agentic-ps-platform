// П10 Лента уведомлений клиента через банк GET /participants/v1/notifications (PS-20 ч. 3 К3.6; РП46 (б) п. 3, (в)):
// подпись запроса участника (RFC 9421), только свои уведомления — участник из проверенной подписи; курсор after —
// notification_id этого участника, иначе 400 REQUEST_INVALID (как лента агента, РП39 п. 7); страница — event_page_max.
import { describe, expect, it } from "vitest";
import { MemoryOperationStore } from "../../src/adp/operations.js";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import { createIssuerEmulator } from "../../src/env/issuer/index.js";
import { MemoryParticipantNotificationStore, type NotificationDraft } from "../../src/participants/notifications.js";
import { TrustedParticipants } from "../../src/participants/trusted.js";
import { ParticipantRequestVerifier } from "../../src/participants/verify.js";
import { buildServer } from "../../src/server.js";
import { createStand } from "../../src/stand/index.js";

const T = new Date("2026-10-20T10:00:00Z");
const PATH = "/participants/v1/notifications";
const declined = (op_ref: string): NotificationDraft => ({
  type: "client.limit_declined",
  key: op_ref,
  data: { principal_ref: "prn_7f3c9a", op_ref, reason: "MANDATE" },
});

function server(pageMax = 100) {
  const emu = createIssuerEmulator();
  const trusted = new TrustedParticipants([emu.trustedKey], { stand: true });
  const notifications = new MemoryParticipantNotificationStore(new MemoryOperationStore());
  const app = buildServer({
    env: "dev",
    participants: {
      trusted,
      consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
      params: { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1, event_page_max: pageMax },
      requests: new ParticipantRequestVerifier(trusted, { skewSec: 300, now: () => T }),
      notifications,
    },
  });
  const get = (query = "", headers = emu.signRequest("GET", PATH, query, T)) =>
    app.inject({ method: "GET", url: query === "" ? PATH : `${PATH}?${query}`, headers });
  return { emu, app, notifications, get };
}

type Feed = { notifications: { notification_id: string; seq: number; type: string; at: string; data: Record<string, unknown> }[] };

describe("ПИ-8 GET /participants/v1/notifications (РП46 (б) п. 3, (в))", () => {
  it("подписанный запрос — 200 со своими уведомлениями по возрастанию seq; after — продолжение; страница — event_page_max", async () => {
    const { emu, app, notifications, get } = server(2);
    try {
      notifications.insertNow(emu.participant_code, ["op-1", "op-2", "op-3"].map(declined), T.toISOString());
      const first = (await get()).json() as Feed;
      expect(first.notifications.map((n) => [n.seq, n.type, n.data.op_ref])).toEqual([
        [1, "client.limit_declined", "op-1"],
        [2, "client.limit_declined", "op-2"],
      ]);
      expect(first.notifications[0]).toEqual({
        notification_id: first.notifications[0]!.notification_id,
        seq: 1,
        type: "client.limit_declined",
        at: T.toISOString(),
        data: { principal_ref: "prn_7f3c9a", op_ref: "op-1", reason: "MANDATE" },
      });
      const q = `after=${first.notifications[1]!.notification_id}`;
      const next = await get(q);
      expect(next.statusCode).toBe(200);
      expect((next.json() as Feed).notifications.map((n) => n.seq)).toEqual([3]);
      const last = `after=${(next.json() as Feed).notifications[0]!.notification_id}`;
      expect((await get(last)).json()).toEqual({ notifications: [] });
    } finally {
      await app.close();
    }
  });

  it("только свои: уведомления другого банка не видны; его курсор — 400, как неизвестный", async () => {
    const { emu, app, notifications, get } = server();
    try {
      notifications.insertNow("bank:other", [declined("op-x")], T.toISOString());
      const [other] = await notifications.page("bank:other", undefined, 10);
      expect((await get()).json(), "банк прочитал уведомление клиента другого банка").toEqual({ notifications: [] });
      const res = await get(`after=${other!.notification_id}`);
      expect(res.statusCode, "курсор другого банка принят").toBe(400);
      expect(res.json()).toEqual({ code: "REQUEST_INVALID" });
      expect(emu.participant_code).not.toBe("bank:other");
    } finally {
      await app.close();
    }
  });

  it("after не по форме, пустой, повторённый, лишний параметр — 400 REQUEST_INVALID", async () => {
    const { app, get } = server();
    try {
      for (const q of ["after=evt_00000000-0000-8000-8000-000000000000", "after=", "after=x&after=y", "from=1", "after=ntf_00000000-0000-8000-8000-000000000000"]) {
        const res = await get(q);
        expect(res.statusCode, q).toBe(400);
        expect(res.json(), q).toEqual({ code: "REQUEST_INVALID" });
      }
    } finally {
      await app.close();
    }
  });

  it("без подписи, повтор nonce, вне окна, чужой запрос в подписи — 401 SIGNATURE_INVALID одним кодом", async () => {
    const { emu, app, get } = server();
    try {
      expect((await app.inject({ method: "GET", url: PATH })).statusCode, "лента без подписи отдана").toBe(401);
      const h = emu.signRequest("GET", PATH, "", T);
      expect((await get("", h)).statusCode).toBe(200);
      expect((await get("", h)).statusCode, "повтор nonce принят").toBe(401);
      expect((await get("", emu.signRequest("GET", PATH, "", new Date(T.getTime() - 301_000)))).statusCode, "метка вне окна принята").toBe(401);
      const signedOther = emu.signRequest("GET", PATH, "after=ntf_00000000-0000-8000-8000-000000000000", T);
      expect((await get("", signedOther)).statusCode, "подпись другого запроса принята").toBe(401);
    } finally {
      await app.close();
    }
  });

  it("стенд: issuer.getNotifications — подписанный запрос банка стенда; без Outbox участника маршрута нет", async () => {
    const stand = createStand();
    stand.setClock(T);
    try {
      expect(await stand.issuer.getNotifications()).toEqual({ statusCode: 200, body: { notifications: [] } });
      expect((await stand.issuer.getNotifications("bad")).statusCode).toBe(400);
    } finally {
      await stand.close();
    }
    const emu = createIssuerEmulator();
    const trusted = new TrustedParticipants([emu.trustedKey], { stand: true });
    const bare = buildServer({
      env: "dev",
      participants: {
        trusted,
        consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
        params: { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 },
        requests: new ParticipantRequestVerifier(trusted, { skewSec: 300, now: () => T }),
      },
    });
    expect((await bare.inject({ method: "GET", url: PATH, headers: emu.signRequest("GET", PATH, "", T) })).statusCode).toBe(404);
    await bare.close();
  });
});
