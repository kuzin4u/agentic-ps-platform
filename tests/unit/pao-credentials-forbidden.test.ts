// Реквизиты карты в теле POST /pao/v1/credentials — 422 CREDENTIALS_FORBIDDEN (ПАО §6; решение владельца по ревью КТ1
// З2, РП47 доп.): до схемы и до захвата ключа идемпотентности; П5 не вызывается; номера нет в журнале процесса.
import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { ConsentJournal, MemoryConsentStore } from "../../src/consent/index.js";
import { hasPaymentDetails } from "../../src/pao/body.js";
import { paoIdempotency } from "../../src/pao/idempotency.js";
import { paoRoutes } from "../../src/pao/routes.js";
import { PaoRequestVerifier } from "../../src/pao/verify.js";
import { AgentKeys, AgentRegistry, InMemoryAgentRegistryStore } from "../../src/registry/index.js";
import { loadParams } from "../../src/shared/config.js";
import type { CredentialRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const CODE = "nspk:agent:no-pan:v1";

/** Контрольная цифра Луна: номер собирается во время теста — литерала номера карты в репозитории нет (guard.py). */
function withLuhn(body: string): string {
  for (let d = 0; d <= 9; d++) {
    const s = body + d;
    let sum = 0;
    for (let i = 0; i < s.length; i++) {
      let x = Number(s[s.length - 1 - i]);
      if (i % 2 === 1) x = x * 2 > 9 ? x * 2 - 9 : x * 2;
      sum += x;
    }
    if (sum % 10 === 0) return s;
  }
  throw new Error("нет контрольной цифры");
}

const PAN = withLuhn("2200" + "0".repeat(11));
const PAN_SPACED = PAN.replace(/(\d{4})(?=\d)/g, "$1 ");
/** Та же серия с неверной контрольной цифрой. */
const NOT_PAN = PAN.slice(0, -1) + String((Number(PAN.at(-1)) + 1) % 10);

async function gateway() {
  const params = loadParams();
  const store = new InMemoryAgentRegistryStore();
  const registry = new AgentRegistry(store, { keys: params });
  const keys = new AgentKeys(store, { keys: params });
  const side = newAgentSide();
  expect(registry.admit(buyerApplication(CODE, side), { contour: "sandbox", operator: "op" }).admitted).toBe(true);
  const lines: string[] = [];
  const calls: CredentialRequest[] = [];
  const app = Fastify({ logger: { level: "info", stream: { write: (l: string) => void lines.push(l) } } });
  await app.register(async (scope) =>
    paoRoutes(scope, {
      verifier: new PaoRequestVerifier(
        { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
        { skewSec: params.signature_skew_sec },
      ),
      keys,
      idempotency: paoIdempotency({ ttlSec: params.idempotency_ttl_sec }),
      params,
      consent: new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" }),
      credentials: {
        issue: async (_agent, input) => {
          calls.push(input);
          return { ok: false, code: "MANDATE_NOT_FOUND" };
        },
      },
    }),
  );
  await app.ready();
  const post = (body: unknown, key = randomUUID()) =>
    signedInject(app, side, CODE, {
      method: "POST",
      path: "/pao/v1/credentials",
      body: typeof body === "string" ? body : JSON.stringify(body),
      headers: { "idempotency-key": key },
    });
  return { app, lines, calls, post };
}

const valid = {
  mandate_id: "mnd_00000000-0000-8000-8000-000000000001",
  order_ref: "ORD-a",
  merchant_id: "MER-1042",
  amount_max: 1_000,
  currency: "RUB",
  kind: "CARD",
};

describe("POST /pao/v1/credentials: реквизиты карты в теле — 422 CREDENTIALS_FORBIDDEN (инвариант 1)", () => {
  it.each([
    ["поле pan", () => ({ ...valid, pan: PAN })],
    ["поле card_number без цифр по Луну", () => ({ ...valid, card_number: "x" })],
    ["поле CVV в другом регистре", () => ({ ...valid, CVV: "x" })],
    ["вложенное поле expiry", () => ({ ...valid, extra: { expiry: "x" } })],
    ["номер в order_ref", () => ({ ...valid, order_ref: `ORD-${PAN}` })],
    ["номер через пробелы в лишнем поле", () => ({ ...valid, note: PAN_SPACED })],
    ["номер числом", () => ({ ...valid, extra: Number(PAN) })],
  ])("%s — 422, retry never, П5 не вызван, номера нет в журнале процесса", async (_name, body) => {
    const g = await gateway();
    const res = await g.post(body());
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: "CREDENTIALS_FORBIDDEN", retry: "never" });
    expect(g.calls).toHaveLength(0);
    const log = g.lines.join("\n");
    expect(log).toContain("платёжные реквизиты — отклонено");
    expect(log.replace(/[ -]/g, "")).not.toContain(PAN);
    expect(res.body).not.toContain(PAN);
    await g.app.close();
  });

  it("ключ идемпотентности не занят: тот же ключ с телом без реквизитов доходит до П5", async () => {
    const g = await gateway();
    const key = randomUUID();
    expect((await g.post({ ...valid, pan: PAN }, key)).statusCode).toBe(422);
    expect((await g.post(valid, key)).statusCode).toBe(404);
    expect(g.calls).toEqual([valid]);
    await g.app.close();
  });

  it("тело без реквизитов, короткие цифры и серии без суммы Луна — к П5; не JSON — по серии", async () => {
    expect(hasPaymentDetails(JSON.stringify(valid))).toBe(false);
    expect(hasPaymentDetails(JSON.stringify({ ...valid, order_ref: "ORD-123456789012" }))).toBe(false);
    expect(hasPaymentDetails(JSON.stringify({ ...valid, order_ref: `ORD-${NOT_PAN}` }))).toBe(false);
    expect(hasPaymentDetails(JSON.stringify({ ...valid, cart: "x" }))).toBe(false);
    expect(hasPaymentDetails(`not json ${PAN}`)).toBe(true);
    expect(hasPaymentDetails("not json")).toBe(false);
    // id мандата — UUID Платформы: серия его цифр через дефисы может пройти Луна, но это не номер карты.
    expect(hasPaymentDetails(JSON.stringify({ ...valid, mandate_id: "mnd_00000000-0000-8000-8000-000000000000" }))).toBe(false);
    // Не по форме MANDATE_ID — сканируется как прочие значения.
    expect(hasPaymentDetails(JSON.stringify({ ...valid, mandate_id: PAN }))).toBe(true);
  });
});
