// ПС09 «Бюджет исчерпан» на стенде (A3 п. 4–5; ФП5, ФП7): DECLINE LIMIT_EXCEEDED и уведомление эмитенту для клиента
// (PS-20 ч. 3 К3.8; РП46 (б), доп. п. 7): уведомитель по сохранённой записи решения ADP вне пути авторизации → лента банка
// с подписью запроса участника → вебхук-сигнал банку стенда. Первое использование и исчерпание лимита клиента — там же.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ps-nine:v1";
const PRINCIPAL = "prn_ps_nine";

/**
 * Порядок уведомлений разных операций в ленте — по началу операции (at записи), при равенстве — по op_ref, а не по порядку
 * решений (РП46 доп. п. 11); часы стенда стоят — сравнение без порядка.
 */
const sorted = <T>(xs: T[]): T[] => [...xs].sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));

type Feed = { notifications: { notification_id: string; seq: number; type: string; data: Record<string, unknown> }[] };

describe("ПС09 на стенде: LIMIT_EXCEEDED и уведомление эмитенту для клиента (A3 п. 5.3)", () => {
  let stand: Stand;
  let side: AgentSide;
  beforeAll(() => {
    stand = createStand();
    stand.setClock(new Date("2026-10-20T09:00:00Z"));
    side = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const pay = () => standPay(stand, side, CODE, PRINCIPAL);
  /** CART под INTENT того же предела: агентская оплата идёт по CART (РП47 п. 2); уведомления — по мандату операции. */
  const parents = new Map<string, string>();
  const mandate = async (amount_limit: number): Promise<string> => {
    const p = pay();
    const parent = await p.mandate({ amount_limit });
    const cart = await p.cart(parent, amount_limit);
    parents.set(cart, parent);
    return cart;
  };
  const auth = (mandate_id: string, amount: number, op_ref?: string) => pay().auth(mandate_id, amount, op_ref);
  const decide = async (m: CanonicalMessage) =>
    parseDecision((await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json(), "adp");
  const feed = async (): Promise<Feed["notifications"]> => ((await stand.issuer.getNotifications()).body as Feed).notifications;

  it("остаток мандата меньше суммы — DECLINE LIMIT_EXCEEDED; уведомление в ленте банка только после прохода уведомителя, повтор op_ref — без второго", async () => {
    const m = await mandate(100_000);
    expect(await decide(await auth(m, 60_000))).toEqual({ decision: "APPROVE", reason: null });
    const op = `OPKC-PS09-${randomUUID()}`;
    const declined = await auth(m, 60_000, op);
    expect(await decide(declined)).toEqual({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    // Вне пути авторизации: до прохода уведомителя ленты по решению нет.
    expect((await feed()).filter((n) => n.data.mandate_id === m)).toEqual([]);
    expect(await decide(declined)).toEqual({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    await stand.notifyParticipants();
    const mine = (await feed()).filter((n) => n.data.mandate_id === m);
    // По родителю INTENT — ничего: уведомления идут по мандату операции (CART), лишнего по родителю нет (повторный проход КТ1 № 4).
    expect((await feed()).filter((n) => n.data.mandate_id === parents.get(m))).toEqual([]);
    expect(sorted(mine.map((n) => [n.type, n.data.op_ref ?? null, n.data.reason ?? null]))).toEqual([
      ["client.limit_declined", op, "MANDATE"],
      ["client.mandate_first_use", null, null],
    ]);
    expect(mine.find((n) => n.type === "client.limit_declined")!.data).toEqual({ principal_ref: PRINCIPAL, mandate_id: m, agent_code: CODE, op_ref: op, reason: "MANDATE" });
    // Сигнал банку — по каждому уведомлению, содержание — из ленты.
    const sent = await stand.deliverParticipantNotifications();
    expect(sent).toBeGreaterThanOrEqual(2);
    expect(stand.issuerWebhook.handled).toEqual(expect.arrayContaining(mine.map((n) => n.notification_id)));
  });

  it("лимит клиента за сутки исчерпан резервом — client.limit_exhausted; следующий отказ — limit_declined с reason CLIENT", async () => {
    expect((await stand.issuer.setLimits(PRINCIPAL, { per_period: 50_000, period: "DAY", currency: "RUB" }, 1)).statusCode).toBe(200);
    const m = await mandate(500_000);
    expect(await decide(await auth(m, 50_000))).toEqual({ decision: "APPROVE", reason: null });
    expect(await decide(await auth(m, 1_000))).toEqual({ decision: "DECLINE", reason: "LIMIT_EXCEEDED" });
    await stand.notifyParticipants();
    const mine = (await feed()).filter((n) => n.data.mandate_id === m);
    // По родителю INTENT — ничего: уведомления идут по мандату операции (CART), лишнего по родителю нет (повторный проход КТ1 № 4).
    expect((await feed()).filter((n) => n.data.mandate_id === parents.get(m))).toEqual([]);
    expect(sorted(mine.map((n) => [n.type, n.data.reason ?? null]))).toEqual([
      ["client.limit_declined", "CLIENT"],
      ["client.limit_exhausted", null],
      ["client.mandate_first_use", null],
    ]);
  });
});
