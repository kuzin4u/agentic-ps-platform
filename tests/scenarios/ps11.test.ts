// ПС11 «Сумма выше порога: подтверждение и повтор» на стенде — целиком (PS-19 ч. 1–3; A5 п. 3, A7 п. 7; РП50, РП51;
// ФП8; инвариант 7): авторизация 3 400 ₽ при пороге 3 000 ₽ → CONFIRMATION_REQUIRED и запрос на итоговые значения →
// confirmation.required в ленте агента → GET → link → страница УПК → код от эмитента → ПИ-8 (подпись UPK,
// instrument_chosen) → confirmation.approved → GET со ссылкой → повтор через продавца новой операцией → APPROVE;
// второй раз — не APPROVE. Путь через приложение банка (ПИ-8 от банка) — остальные тесты файла.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:ps-eleven:v1";
const PRINCIPAL = "prn_ps_eleven";
const ORDER = "ORD-ps11";
const AMOUNT = 340_000;

describe("ПС11 на стенде: подтверждение выше порога на странице УПК и в приложении эмитента, повтор с confirmation_ref (РП50, РП51)", () => {
  let stand: Stand;
  let side: AgentSide;
  let cartId: string;
  let cred: Credential;
  beforeAll(async () => {
    stand = createStand();
    stand.setClock(new Date("2026-10-22T09:00:00Z"));
    side = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    const intentId = await mandate({ type: "INTENT", amount_limit: 5_000_000, subject: "техника" });
    cartId = await mandate({
      type: "CART",
      parent_id: intentId,
      amount_limit: 2_000_000,
      subject: "корзина SHOP-1042",
      cart: { merchant_id: "MER-1042", items: [{ sku: "kettle", qty: 1, price: AMOUNT }], total: AMOUNT },
    });
    const res = await call("POST", "/pao/v1/credentials", {
      mandate_id: cartId,
      order_ref: ORDER,
      merchant_id: "MER-1042",
      amount_max: AMOUNT,
      currency: "RUB",
      kind: "CARD",
    });
    expect(res.statusCode).toBe(201);
    cred = res.json() as Credential;
  });
  afterAll(async () => stand.close());

  const call = (method: "GET" | "POST", path: string, body?: unknown) =>
    signedInject(stand.app, side, CODE, {
      method,
      path,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "idempotency-key": randomUUID() },
      now: stand.now(),
    });

  async function mandate(over: Partial<MandateRequest>): Promise<string> {
    const req: MandateRequest = {
      type: "INTENT",
      subject: "s",
      amount_limit: 1,
      currency: "RUB",
      valid_to: "2026-10-26T00:00:00Z",
      merchant_scope: ["MER-1042"],
      principal_ref: PRINCIPAL,
      mode: "IMMEDIATE",
      ...over,
    };
    const res = await call("POST", "/pao/v1/mandates", req);
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect((await stand.issuer.sign(id)).statusCode).toBe(200);
    return id;
  }

  /** Сообщение процессинга — прямо в ADP стенда (путь эквайрер → ОПКЦ — PS-11). */
  const auth = (op_ref: string, over: Partial<CanonicalMessage> = {}): CanonicalMessage => ({
    op_ref,
    msg_type: "AUTH_REQUEST",
    channel: "CARD",
    amount: AMOUNT,
    currency: "RUB",
    merchant: { id: "MER-1042", mcc: "5462" },
    instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
    aoi: cred.aoi,
    order_ref: ORDER,
    ...over,
  });
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const key = { mandate_id: "", merchant_id: "MER-1042", order_ref: ORDER, amount: AMOUNT, currency: "RUB" };

  /** Лента агента — массив событий (РП39). */
  type Feed = readonly { readonly type: string; readonly data: Record<string, unknown> }[];
  const feed = async (): Promise<Feed> => (await call("GET", "/pao/v1/events")).json() as Feed;

  it("доказательный, целиком через страницу УПК: событие → GET → link → код → решение человека → событие → GET со ссылкой → APPROVE; второй раз — нет", async () => {
    const order = "ORD-ps11-upk";
    const c = (await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: order, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" })).json() as Credential;
    const m = (op_ref: string, confirmation_ref?: string): CanonicalMessage => ({
      ...auth(op_ref),
      order_ref: order,
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
      ...(confirmation_ref ? { confirmation_ref } : {}),
    });
    expect(parseDecision(await decide(m("OPKC-PS11-U1")), "adp")).toEqual({ decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED" });

    // Агент: событие-сигнал → GET → link человеку; сам на странице ничего не делает (Т7).
    const required = (await feed()).filter((e) => e.type === "confirmation.required").at(-1)!;
    const id = required.data.confirmation_id as string;
    const view = (await call("GET", `/pao/v1/confirmations/${id}`)).json() as { status: string; link: string; confirmation_ref: string | null };
    expect(view).toMatchObject({ status: "PENDING", confirmation_ref: null });
    const link = new URL(view.link);
    expect(link.origin).toBe(stand.params.upk_page_base_url);
    expect(link.pathname).toBe(`/c/${id}`);

    // Человек: страница УПК по link — итог из записи П6; код получил в банке (вне ПАО).
    const pageRes = await stand.upk.app.inject({ method: "GET", url: link.pathname });
    expect(pageRes.statusCode).toBe(200);
    expect(pageRes.body).toMatch(/data-amount>3\s?400,00\s?₽</);
    expect(pageRes.body).toContain(`data-order>${order}<`);
    const code = await stand.issuer.upkCode(id);
    const submit = (form: Record<string, string>) =>
      stand.upk.app.inject({
        method: "POST",
        url: link.pathname,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        payload: new URLSearchParams(form).toString(),
      });
    const done = await submit({ code: code!, instrument: "CARD", decision: "APPROVE" });
    expect(done.statusCode).toBe(200);
    expect(done.body).toContain("data-status>APPROVED<");
    expect(done.body, "confirmation_ref человеку не показывается — его видит только агент (РП50 п. 7)").not.toContain("cr_");
    expect((await stand.confirmations.get(id))?.decision).toMatchObject({ participant_code: "stand:upk-emulator", instrument_chosen: "CARD" });

    // Агент: confirmation.approved → GET со ссылкой → повтор через продавца новой операцией.
    expect((await feed()).filter((e) => e.type === "confirmation.approved" && e.data.confirmation_id === id)).toHaveLength(1);
    const approved = (await call("GET", `/pao/v1/confirmations/${id}`)).json() as { status: string; confirmation_ref: string };
    expect(approved.status).toBe("APPROVED");
    expect(parseDecision(await decide(m("OPKC-PS11-U2", approved.confirmation_ref)), "adp")).toEqual({ decision: "APPROVE", reason: null });
    expect((await stand.confirmations.get(id))?.status).toBe("USED");
    expect(parseDecision(await decide(m("OPKC-PS11-U3", approved.confirmation_ref)), "adp").decision, "второй раз — не APPROVE").not.toBe("APPROVE");
    // Страница после погашения: запрос уже USED — 409 по статусу, до кода; второго решения нет. Одноразовость кода через
    // страницу — tests/unit/upk-page.test.ts.
    expect((await submit({ code: code!, instrument: "CARD", decision: "APPROVE" })).statusCode).toBe(409);
    expect(done.body).not.toContain(approved.confirmation_ref);
  });

  it("доказательный: 3 400 ₽ → CONFIRMATION_REQUIRED и запрос; банк подтверждает итог → ссылка; повтор с ней → APPROVE; второй раз — нет", async () => {
    const first = await decide(auth("OPKC-PS11-1"));
    expect(parseDecision(first, "adp")).toEqual({ decision: "CONFIRMATION_REQUIRED", reason: "CONFIRMATION_REQUIRED" });
    expect(first.split_detected).toBe(false);

    const [req, ...rest] = await stand.confirmations.byKey({ ...key, mandate_id: cartId });
    expect(rest).toEqual([]);
    expect(req).toMatchObject({ agent_code: CODE, mandate_id: cartId, merchant_id: "MER-1042", amount: AMOUNT, currency: "RUB", order_ref: ORDER, status: "PENDING" });

    // Человек видит итог в приложении банка и подтверждает; банк подписывает запись над totals_hash этого итога.
    const ok = await stand.issuer.confirm(req!.confirmation_id);
    expect(ok.statusCode).toBe(200);
    const { confirmation_ref } = ok.body as { confirmation_ref: string; status: string };
    expect(ok.body).toMatchObject({ confirmation_id: req!.confirmation_id, status: "APPROVED" });

    // Повтор через продавца — новой операцией с той же криптограммой заказа и ссылкой (Дополнения РП50 п. 7).
    const retry = await decide(auth("OPKC-PS11-2", { confirmation_ref }));
    expect(parseDecision(retry, "adp")).toEqual({ decision: "APPROVE", reason: null });
    expect((await stand.confirmations.get(req!.confirmation_id))?.status).toBe("USED");

    // Однократно: та же ссылка ещё раз — не одобрение (A7 п. 7.3), нового запроса на заказ нет.
    const again = await decide(auth("OPKC-PS11-3", { confirmation_ref }));
    expect(parseDecision(again, "adp").decision).not.toBe("APPROVE");
    expect(await stand.confirmations.byKey({ ...key, mandate_id: cartId })).toHaveLength(1);
  });

  it("ссылка привязана к итогу: тот же заказ с другой суммой — CONFIRMATION_REQUIRED, ссылка не погашена", async () => {
    const order = "ORD-ps11-b";
    const c = (await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: order, merchant_id: "MER-1042", amount_max: 400_000, currency: "RUB", kind: "CARD" })).json() as Credential;
    const m = (op_ref: string, amount: number, confirmation_ref?: string): CanonicalMessage => ({
      ...auth(op_ref),
      amount,
      order_ref: order,
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
      ...(confirmation_ref ? { confirmation_ref } : {}),
    });
    expect((await decide(m("OPKC-PS11-B1", 350_000))).decision).toBe("CONFIRMATION_REQUIRED");
    const [req] = await stand.confirmations.byKey({ mandate_id: cartId, merchant_id: "MER-1042", order_ref: order, amount: 350_000, currency: "RUB" });
    const { confirmation_ref } = (await stand.issuer.confirm(req!.confirmation_id)).body as { confirmation_ref: string };
    expect((await decide(m("OPKC-PS11-B2", 360_000, confirmation_ref))).decision).toBe("CONFIRMATION_REQUIRED");
    expect((await stand.confirmations.get(req!.confirmation_id))?.status).toBe("APPROVED");
  });

  it("отказ человека — REJECTED, ссылки нет; повтор заказа — CONFIRMATION_REQUIRED без нового запроса", async () => {
    const order = "ORD-ps11-c";
    const c = (await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: order, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" })).json() as Credential;
    const m = (op_ref: string): CanonicalMessage => ({
      ...auth(op_ref),
      order_ref: order,
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
    });
    await decide(m("OPKC-PS11-C1"));
    const k = { mandate_id: cartId, merchant_id: "MER-1042", order_ref: order, amount: AMOUNT, currency: "RUB" };
    const [req] = await stand.confirmations.byKey(k);
    expect((await stand.issuer.confirm(req!.confirmation_id, { decision: "REJECT" })).body).toEqual({ confirmation_id: req!.confirmation_id, status: "REJECTED" });
    expect((await decide(m("OPKC-PS11-C2"))).decision).toBe("CONFIRMATION_REQUIRED");
    expect((await stand.confirmations.byKey(k)).map((x) => x.status)).toEqual(["REJECTED"]);
  });

  it("решение после order_hold_sec — 409 EXPIRED, ссылки нет", async () => {
    const order = "ORD-ps11-d";
    const c = (await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref: order, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" })).json() as Credential;
    await decide({
      ...auth("OPKC-PS11-D1"),
      order_ref: order,
      instrument: { kind: "AGENT_TOKEN", token_ref: c.payload.token_ref as string, cryptogram: c.payload.cryptogram as string },
    });
    const [req] = await stand.confirmations.byKey({ mandate_id: cartId, merchant_id: "MER-1042", order_ref: order, amount: AMOUNT, currency: "RUB" });
    stand.setClock(new Date(Date.parse(req!.expires_at)));
    const res = await stand.issuer.confirm(req!.confirmation_id);
    expect([res.statusCode, res.body]).toEqual([409, { code: "CONFIRMATION_NOT_PENDING", status: "EXPIRED" }]);
  });
});
