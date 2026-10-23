// Операции по мандату (PS-16 ч. 3, РП55 п. 6): GET /pao/v1/operations?mandate_id — массив Operation этого агента по
// мандату записи ADP, только с итогом, по времени решения; операции CART при запросе по INTENT не входят. Чужой,
// неизвестный, не по форме и без параметра мандат — 404 MANDATE_NOT_FOUND; записей больше event_page_max — 400
// REQUEST_INVALID (постраничный вывод — ПАО 1.5.0); SUSPENDED — 403.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";

const CODE = "nspk:agent:ops-list:v1";
const OTHER = "nspk:agent:ops-list-other:v1";
const T0 = new Date("2026-10-23T14:00:00Z");
/** Малый предел списка: event_page_max стенда — 100, тест проверяет границу на 3. */
const PAGE_MAX = 3;

const opRef = (): string => `OPKC-LIST-${letters(12)}`;

describe("GET /pao/v1/operations?mandate_id на стенде (РП55 п. 6)", () => {
  let stand: Stand;
  let side: AgentSide;
  let other: AgentSide;
  let dir: string;
  const prevPath = process.env.PARAMS_PATH;
  const principal = opaquePrincipalRef("prn_list_");
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "ops-list-"));
    const params = JSON.parse(readFileSync(new URL("../../config/params.stand.json", import.meta.url), "utf8")) as Record<string, unknown>;
    writeFileSync(join(dir, "params.json"), JSON.stringify({ ...params, event_page_max: PAGE_MAX }));
    process.env.PARAMS_PATH = join(dir, "params.json");
    stand = createStand();
    stand.setClock(T0);
    side = newAgentSide();
    other = newAgentSide();
    expect(stand.admit(buyerApplication(CODE, side), "op").admitted).toBe(true);
    expect(stand.admit(buyerApplication(OTHER, other), "op").admitted).toBe(true);
  });
  afterAll(async () => {
    if (prevPath === undefined) delete process.env.PARAMS_PATH;
    else process.env.PARAMS_PATH = prevPath;
    await stand.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const pay = () => standPay(stand, side, CODE, principal);
  const decide = async (m: CanonicalMessage): Promise<Decision> =>
    (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: m })).json() as Decision;
  const pi3 = async (payload: Record<string, unknown>) => (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
  /** q — строка запроса с «?» или пустая; подпись покрывает её отдельно от пути (signedInject.query). */
  const list = (s: AgentSide, code: string, q: string) => signedInject(stand.app, s, code, { method: "GET", path: "/pao/v1/operations", query: q.replace(/^\?/, ""), now: stand.now() });
  const tick = (ms: number) => stand.setClock(new Date(stand.now().getTime() + ms));

  it("свои операции по CART с итогом, по времени: SETTLED, REVERSED; без итога (APPROVE до эмитента) не входит; по INTENT — пусто", async () => {
    const intent = await pay().mandate({ amount_limit: 100_000 });
    const cart = await pay().cart(intent, 100_000);
    const s = opRef();
    expect(await decide(await pay().auth(cart, 20_000, s))).toMatchObject({ decision: "APPROVE" });
    expect(await pi3({ op_ref: s, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    expect(await pi3({ op_ref: s, msg_type: "PRESENTMENT", amount: 20_000, currency: "RUB" })).toBe(202);
    tick(1_000);
    const pending = opRef();
    expect(await decide(await pay().auth(cart, 5_000, pending))).toMatchObject({ decision: "APPROVE" });
    tick(1_000);
    const r = opRef();
    expect(await decide(await pay().auth(cart, 5_000, r))).toMatchObject({ decision: "APPROVE" });
    expect(await pi3({ op_ref: r, msg_type: "REVERSAL" })).toBe(202);
    const res = await list(side, CODE, `?mandate_id=${cart}`);
    expect(res.statusCode).toBe(200);
    const ops = res.json() as { op_ref: string; status: string }[];
    expect(ops.map((o) => [o.op_ref, o.status])).toEqual([
      [s, "SETTLED"],
      [r, "REVERSED"],
    ]);
    const byIntent = await list(side, CODE, `?mandate_id=${intent}`);
    expect(byIntent.statusCode).toBe(200);
    expect(byIntent.json()).toEqual([]);
  });

  it("записей больше event_page_max — 400 REQUEST_INVALID, а не урезанный список; ровно предел — 200", async () => {
    const intent = await pay().mandate({ amount_limit: 100_000 });
    const cart = await pay().cart(intent, 100_000);
    for (let i = 0; i < PAGE_MAX; i++) {
      const o = opRef();
      expect(await decide(await pay().auth(cart, 1_000, o))).toMatchObject({ decision: "APPROVE" });
      expect(await pi3({ op_ref: o, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
      tick(10);
    }
    const full = await list(side, CODE, `?mandate_id=${cart}`);
    expect(full.statusCode).toBe(200);
    expect((full.json() as { status: string }[]).map((o) => o.status)).toEqual(Array(PAGE_MAX).fill("AUTHORIZED"));
    expect(await decide(await pay().auth(cart, 1_000, opRef()))).toMatchObject({ decision: "APPROVE" });
    const over = await list(side, CODE, `?mandate_id=${cart}`);
    expect(over.statusCode).toBe(400);
    expect(over.json()).toMatchObject({ code: "REQUEST_INVALID" });
  });

  it("чужой, неизвестный, не по форме и без параметра мандат — 404 MANDATE_NOT_FOUND одним ответом", async () => {
    const intent = await pay().mandate({ amount_limit: 100_000 });
    const cart = await pay().cart(intent, 100_000);
    for (const [s, code, q] of [
      [other, OTHER, `?mandate_id=${cart}`],
      [side, CODE, "?mandate_id=mnd_nope"],
      [side, CODE, "?mandate_id=../x"],
      [side, CODE, ""],
    ] as const) {
      const res = await list(s, code, q);
      expect(res.statusCode, q).toBe(404);
      expect(res.json(), q).toMatchObject({ code: "MANDATE_NOT_FOUND" });
    }
  });
});
