// РП75 п. 3, п. 5 (#112): Н-02 — второй реквизит на новый запрос того же заказа (подмена П5 в сборке стенда, один раз);
// повтор под тем же Idempotency-Key не затрагивается; StandCall.fault у изменённых сбоем обращений (Н-02, Н-12).
import { afterEach, describe, expect, it } from "vitest";
import { createStand, type Stand } from "../../src/stand/index.js";
import { demoFlow } from "../support/demo-flow.js";

const T0 = new Date("2026-11-08T10:00:00Z");
const at = (ms: number) => new Date(T0.getTime() + ms);
const AMOUNT = 100_000;

const opened: Stand[] = [];
const open = (demo: boolean): Stand => {
  const s = createStand(demo ? { demo: { faults: true } } : {});
  s.setClock(T0);
  opened.push(s);
  return s;
};
afterEach(async () => {
  await Promise.all(opened.splice(0).map((s) => s.close()));
});

const faultLog = (s: Stand) => (s.demo?.log() ?? []).filter((e) => e.what !== "ARMED" && e.what !== "DISARMED");
const credentialCalls = (s: Stand) => s.calls().filter((c) => c.method === "POST" && c.path === "/pao/v1/credentials");

describe("Н-02 (R23, R25): второй реквизит на повтор запроса", () => {
  it("новый запрос того же заказа — новый реквизит, запись SECOND_CREDENTIAL_ISSUED, StandCall.fault; один раз", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-cred-1:v1");
    const first = await f.credential("ORD-cred-1", AMOUNT);
    expect(first.statusCode).toBe(201);
    s.demo!.arm("Н-02");
    s.setClock(at(1000));
    const second = await f.credential("ORD-cred-1", AMOUNT);
    expect(second.statusCode).toBe(201);
    expect(second.body.credential_ref).not.toBe(first.body.credential_ref);
    expect(second.body.payload.cryptogram).not.toBe(first.body.payload.cryptogram);
    expect(faultLog(s).map((e) => [e.test, e.what, e.ids])).toEqual([
      ["Н-02", "SECOND_CREDENTIAL_ISSUED", { mandate_id: second.body.aoi.mandate_id, merchant_id: "MER-1042", order_ref: "ORD-cred-1" }],
    ]);
    // Сбой снят: следующий повтор — реквизит заказа (первый), без пометки.
    s.setClock(at(2000));
    const third = await f.credential("ORD-cred-1", AMOUNT);
    expect(third.body.credential_ref).toBe(first.body.credential_ref);
    expect(credentialCalls(s).map((c) => c.fault)).toEqual([undefined, "Н-02", undefined]);
    expect(faultLog(s)).toHaveLength(1);
  });

  it("второй реквизит настоящий для ADP и чтений: APPROVE по его криптограмме, GET по ссылке — 200", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-cred-2:v1");
    await f.credential("ORD-cred-2", AMOUNT);
    s.demo!.arm("Н-02");
    s.setClock(at(1000));
    const second = (await f.credential("ORD-cred-2", AMOUNT)).body;
    expect((await f.authorize(second, "ORD-cred-2", AMOUNT, "OPKC-ORD-cred-2-2")).decision).toBe("APPROVE");
  });

  it("повтор под тем же Idempotency-Key — прежний ответ, сбой не срабатывает и остаётся включённым", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-cred-3:v1");
    const first = await f.credential("ORD-cred-3", AMOUNT, "key-cred-3");
    s.demo!.arm("Н-02");
    s.setClock(at(1000));
    const replay = await f.credential("ORD-cred-3", AMOUNT, "key-cred-3");
    expect(replay.statusCode).toBe(201);
    expect(replay.body.credential_ref).toBe(first.body.credential_ref);
    expect(faultLog(s)).toEqual([]);
    expect(credentialCalls(s).every((c) => c.fault === undefined)).toBe(true);
    // Сбой остался включённым: новый запрос — второй реквизит.
    expect((await f.credential("ORD-cred-3", AMOUNT)).body.credential_ref).not.toBe(first.body.credential_ref);
  });

  it("первый запрос заказа и повтор без arm — как обычно; та же криптограмма (те же часы) — обычный повтор, сбой не сработал", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-cred-4:v1");
    s.demo!.arm("Н-02");
    const first = await f.credential("ORD-cred-4", AMOUNT);
    expect(faultLog(s)).toEqual([]);
    // Часы те же — срок и криптограмма те же: второй реквизит с чужой криптограммой не пишется.
    const same = await f.credential("ORD-cred-4", AMOUNT);
    expect(same.body.credential_ref).toBe(first.body.credential_ref);
    expect(faultLog(s)).toEqual([]);
    s.demo!.disarm("Н-02");
    s.setClock(at(1000));
    expect((await f.credential("ORD-cred-4", AMOUNT)).body.credential_ref).toBe(first.body.credential_ref);
    expect(faultLog(s)).toEqual([]);
  });
});

describe("РП75 п. 5: StandCall.fault", () => {
  it("Н-12: помечено каждое чтение ленты, из которого задержано событие; прочие — без поля", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-call-12:v1");
    s.demo!.arm("Н-12", { delay_ms: 1000 });
    await f.approve("ORD-call-12");
    await f.feed();
    await f.feed();
    s.setClock(at(1000));
    await f.feed();
    const feeds = s.calls().filter((c) => c.path === "/pao/v1/events");
    expect(feeds.map((c) => c.fault)).toEqual(["Н-12", "Н-12", undefined]);
  });

  it("обычный стенд — поля fault нет ни у одного обращения", async () => {
    const s = open(false);
    const f = await demoFlow(s, "nspk:agent:demo-call-0:v1");
    await f.credential("ORD-call-0", AMOUNT);
    await f.credential("ORD-call-0", AMOUNT);
    await f.feed();
    expect(s.calls().length).toBeGreaterThan(0);
    expect(s.calls().some((c) => "fault" in c)).toBe(false);
  });
});
