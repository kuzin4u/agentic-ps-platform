// РП75 п. 3 (#112): Н-11 — банк стенда «утекает» код страницы УПК, в журнал только метка без значения; Н-12 — позднее
// событие итога в ленте агента: задержка или перестановка пары, событие не теряется (инвариант 9).
import { afterEach, describe, expect, it } from "vitest";
import { createStand, type Stand } from "../../src/stand/index.js";
import { demoFlow } from "../support/demo-flow.js";

const T0 = new Date("2026-11-08T10:00:00Z");
const at = (ms: number) => new Date(T0.getTime() + ms);

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
const types = (evs: readonly { type: string }[]) => evs.map((e) => e.type);

describe("Н-11 (R20): утечка кода подтверждения — только метка", () => {
  async function confirmation(s: Stand): Promise<string> {
    const f = await demoFlow(s, "nspk:agent:demo-upk:v1");
    const { decision } = await f.decide("ORD-upk-1", 340_000);
    expect(decision.decision).toBe("CONFIRMATION_REQUIRED");
    return (await f.feed()).at(-1)!.data.confirmation_id as string;
  }

  it("со сбоем: код выдан как обычно, в журнале UPK_CODE_LEAKED с confirmation_id, значения кода в журнале нет", async () => {
    const s = open(true);
    const id = await confirmation(s);
    s.demo!.arm("Н-11");
    const code = await s.issuer.upkCode(id);
    expect(typeof code).toBe("string");
    expect(faultLog(s)).toEqual([{ seq: 2, at: T0.toISOString(), kind: "fault", test: "Н-11", what: "UPK_CODE_LEAKED", ids: { confirmation_id: id } }]);
    expect(JSON.stringify(s.demo!.log())).not.toContain(code!);
  });

  it("без arm — записи нет; неизвестный запрос — undefined и записи нет", async () => {
    const s = open(true);
    const id = await confirmation(s);
    expect(typeof (await s.issuer.upkCode(id))).toBe("string");
    s.demo!.arm("Н-11");
    expect(await s.issuer.upkCode("cnf_unknown")).toBeUndefined();
    expect(faultLog(s)).toEqual([]);
  });
});

describe("Н-12 (R31): позднее событие итога в ленте агента", () => {
  it("без сбоя (демо и обычный стенд) — operation.authorized в ленте сразу", async () => {
    for (const s of [open(true), open(false)]) {
      const f = await demoFlow(s, "nspk:agent:demo-late-0:v1");
      await f.approve("ORD-late-0");
      expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed", "operation.authorized"]);
      expect(faultLog(s)).toEqual([]);
    }
  });

  it("задержка: итог не виден до delay_ms, курсор его не перешагивает, потом приходит; запись — одна", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-late-1:v1");
    s.demo!.arm("Н-12", { delay_ms: 2000 });
    const op_ref = await f.approve("ORD-late-1");
    const early = await f.feed();
    expect(types(early)).toEqual(["mandate.signed", "mandate.signed"]);
    expect(await f.feed(early.at(-1)!.event_id)).toEqual([]);
    s.setClock(at(1999));
    expect(types(await f.feed(early.at(-1)!.event_id))).toEqual([]);
    s.setClock(at(2000));
    const late = await f.feed(early.at(-1)!.event_id);
    expect(types(late)).toEqual(["operation.authorized"]);
    expect(late[0]!.data.op_ref).toBe(op_ref);
    expect(await f.feed(late[0]!.event_id)).toEqual([]);
    expect(faultLog(s).map((e) => [e.test, e.what, e.ids])).toEqual([["Н-12", "OUTCOME_EVENT_DELAYED", { op_ref }]]);
  });

  it("задержка по умолчанию — event_reorder_window_ms стенда", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-late-2:v1");
    s.demo!.arm("Н-12");
    await f.approve("ORD-late-2");
    s.setClock(at(s.params.event_reorder_window_ms - 1));
    expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed"]);
    s.setClock(at(s.params.event_reorder_window_ms));
    expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed", "operation.authorized"]);
  });

  it("перестановка: пара итогов — в обратном порядке, младший приходит ещё раз следующим чтением; запись — одна", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-late-3:v1");
    s.demo!.arm("Н-12", { reorder: true });
    const op1 = await f.approve("ORD-late-3a");
    // Пары ещё нет — первый итог ждёт второго.
    expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed"]);
    const op2 = await f.approve("ORD-late-3b");
    const page = await f.feed();
    expect(page.slice(2).map((e) => e.data.op_ref)).toEqual([op2, op1]);
    const again = await f.feed(page.at(-1)!.event_id);
    expect(again.map((e) => e.data.op_ref)).toEqual([op2]);
    expect(again[0]!.event_id).toBe(page[2]!.event_id);
    expect(await f.feed(again[0]!.event_id)).toEqual([]);
    expect(faultLog(s).map((e) => [e.what, e.ids])).toEqual([["OUTCOME_EVENTS_REORDERED", { op_ref: op2 }]]);
  });

  it("перестановка без пары: первый итог ждёт не дольше задержки и приходит как есть", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-late-4:v1");
    s.demo!.arm("Н-12", { reorder: true, delay_ms: 1000 });
    await f.approve("ORD-late-4");
    expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed"]);
    s.setClock(at(1000));
    expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed", "operation.authorized"]);
    expect(faultLog(s)).toEqual([]);
  });

  it("disarm — лента снова без задержки; delay_ms и reorder проверяются при arm", async () => {
    const s = open(true);
    const f = await demoFlow(s, "nspk:agent:demo-late-5:v1");
    const d = s.demo!;
    expect(() => d.arm("Н-12", { delay_ms: 0 })).toThrow(/delay_ms — целое/);
    expect(() => d.arm("Н-12", { delay_ms: 60_001 })).toThrow(/delay_ms — целое/);
    expect(() => d.arm("Н-12", { delay_ms: 1.5 })).toThrow(/delay_ms — целое/);
    expect(() => d.arm("Н-12", { reorder: "yes" } as never)).toThrow(/reorder — булево/);
    d.arm("Н-12", { delay_ms: 60_000 });
    await f.approve("ORD-late-5");
    expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed"]);
    d.disarm("Н-12");
    expect(types(await f.feed())).toEqual(["mandate.signed", "mandate.signed", "operation.authorized"]);
  });
});
