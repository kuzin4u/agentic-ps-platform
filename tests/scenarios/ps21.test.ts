// ПС21 «Выбор инструмента человеком на странице УПК» на стенде — частично до PS-21 (РП51 п. 13–16, остаточный риск 4;
// F26; A5 п. 3.2; ФП8): тест явно включает upk_sbp_enabled (PARAMS_PATH — копия стендовых параметров). Человек выбрал
// СБП — confirmation_ref выдан с instrument_chosen: SBP; повтор по карте с этой ссылкой — CONFIRMATION_REQUIRED (ссылка
// только по выбранному инструменту); выбор карты — APPROVE по карте. Агент инструмент не выбирает: в ПАО поля нет, решение
// приходит со страницы (UPK) по коду человека. «Повтор по выбранному СБП» — после PS-21 (путь СБП в ADP), без обхода.
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { parseDecision } from "../../src/shared/codes.js";
import type { Credential, MandateRequest } from "../../src/shared/pao.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:ps-twenty-one:v1";
const PRINCIPAL = "prn_ps_twenty_one";
const AMOUNT = 340_000;

describe("ПС21 на стенде (частично до PS-21): человек выбирает инструмент на странице УПК, ссылка — только по нему", () => {
  let stand: Stand;
  let side: AgentSide;
  let cartId: string;
  let dir: string;
  const savedPath = process.env.PARAMS_PATH;

  beforeAll(async () => {
    // upk_sbp_enabled: true — только в этом тесте (по умолчанию false до PS-21, РП51 п. 16).
    dir = mkdtempSync(join(tmpdir(), "ps21-"));
    const params = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../config/params.stand.json"), "utf8")) as Record<string, unknown>;
    const path = join(dir, "params.json");
    writeFileSync(path, JSON.stringify({ ...params, upk_sbp_enabled: true }));
    process.env.PARAMS_PATH = path;
    stand = createStand();
    expect(stand.params.upk_sbp_enabled).toBe(true);
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
  });
  afterAll(async () => {
    await stand?.close();
    if (savedPath === undefined) delete process.env.PARAMS_PATH;
    else process.env.PARAMS_PATH = savedPath;
    rmSync(dir, { recursive: true, force: true });
  });

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

  /** Заказ: реквизит по карте, первая авторизация — CONFIRMATION_REQUIRED, запрос и link из GET агента. */
  async function order(order_ref: string) {
    const res = await call("POST", "/pao/v1/credentials", { mandate_id: cartId, order_ref, merchant_id: "MER-1042", amount_max: AMOUNT, currency: "RUB", kind: "CARD" });
    expect(res.statusCode).toBe(201);
    const cred = res.json() as Credential;
    const auth = (op_ref: string, confirmation_ref?: string): CanonicalMessage => ({
      op_ref,
      msg_type: "AUTH_REQUEST",
      channel: "CARD",
      amount: AMOUNT,
      currency: "RUB",
      merchant: { id: "MER-1042", mcc: "5462" },
      instrument: { kind: "AGENT_TOKEN", token_ref: cred.payload.token_ref as string, cryptogram: cred.payload.cryptogram as string },
      aoi: cred.aoi,
      order_ref,
      ...(confirmation_ref ? { confirmation_ref } : {}),
    });
    const decide = async (m: CanonicalMessage): Promise<Decision> =>
      (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
    expect(parseDecision(await decide(auth(`OPKC-${order_ref}-1`)), "adp").decision).toBe("CONFIRMATION_REQUIRED");
    const [req] = await stand.confirmations.byKey({ mandate_id: cartId, merchant_id: "MER-1042", order_ref, amount: AMOUNT, currency: "RUB" });
    const view = (await call("GET", `/pao/v1/confirmations/${req!.confirmation_id}`)).json() as { link: string };
    return { id: req!.confirmation_id, path: new URL(view.link).pathname, auth, decide };
  }

  /** Человек на странице УПК: выбор инструмента и код из банка. */
  const choose = async (path: string, id: string, instrument: "CARD" | "SBP") => {
    const code = await stand.issuer.upkCode(id);
    return stand.upk.app.inject({
      method: "POST",
      url: path,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ code: code!, instrument, decision: "APPROVE" }).toString(),
    });
  };

  it("страница предлагает карту и СБП (upk_sbp_enabled: true)", async () => {
    const { path } = await order("ORD-ps21-page");
    const html = (await stand.upk.app.inject({ method: "GET", url: path })).body;
    expect(html).toContain('value="CARD"');
    expect(html).toContain('value="SBP"');
  });

  it("человек выбрал СБП — ссылка выдана с instrument_chosen: SBP; повтор по карте с ней — CONFIRMATION_REQUIRED, ссылка не погашена", async () => {
    const { id, path, auth, decide } = await order("ORD-ps21-sbp");
    expect((await choose(path, id, "SBP")).statusCode).toBe(200);
    const rec = await stand.confirmations.get(id);
    expect(rec).toMatchObject({ status: "APPROVED", decision: { participant_code: "stand:upk-emulator", instrument_chosen: "SBP" } });
    const view = (await call("GET", `/pao/v1/confirmations/${id}`)).json() as { status: string; confirmation_ref: string };
    expect(view.status).toBe("APPROVED");
    expect(parseDecision(await decide(auth("OPKC-ORD-ps21-sbp-2", view.confirmation_ref)), "adp")).toEqual({
      decision: "CONFIRMATION_REQUIRED",
      reason: "CONFIRMATION_REQUIRED",
    });
    expect((await stand.confirmations.get(id))?.status, "ссылка не погашена").toBe("APPROVED");
  });

  it("человек выбрал карту — повтор по карте с ссылкой APPROVE", async () => {
    const { id, path, auth, decide } = await order("ORD-ps21-card");
    expect((await choose(path, id, "CARD")).statusCode).toBe(200);
    const view = (await call("GET", `/pao/v1/confirmations/${id}`)).json() as { confirmation_ref: string };
    expect(parseDecision(await decide(auth("OPKC-ORD-ps21-card-2", view.confirmation_ref)), "adp")).toEqual({ decision: "APPROVE", reason: null });
    expect((await stand.confirmations.get(id))?.decision?.instrument_chosen).toBe("CARD");
  });

  it("агент инструмент не выбирает: в ПАО поля нет — POST /pao/v1/confirmations в 1.4.x не принимается (РП51 п. 11)", async () => {
    const res = await call("POST", "/pao/v1/confirmations", { instrument_chosen: "SBP" });
    expect(res.statusCode).toBe(400);
  });

  it.todo("повтор по выбранному СБП (ACCOUNT_LINK, канал SBP) — APPROVE: после PS-21, путь СБП в ADP (РП43 п. 7, РП51 п. 16)");
});
