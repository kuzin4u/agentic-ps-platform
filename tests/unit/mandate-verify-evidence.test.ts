// П2 verify и выписка (PS-06 К2.7, К2.8; РП38 п. 6–7, A7 п. 9.2–9.3): verify — без предмета, остаток — из П3 (РП41 п. 10; тесты остатка — state-exhausted.test.ts);
// выписка — цепочка журнала, по которой хэши, Mandate.hash и подписи банка проверяются без Платформы; соли предмета нет.
import { createPublicKey, randomUUID, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { AsyncHashChainJournal, chainGenesis, entryHash } from "@kuzin4u/agentic-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore } from "../../src/consent/store.js";
import type { MandateDecisionPayload, MandateRevocationPayload } from "../../src/consent/model.js";
import { participantRevocationSigningInput, participantSigningInput } from "../../src/participants/trusted.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import type { JournalRecord, MandateRequest } from "../../src/shared/pao.js";
import { buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { signedInject } from "../support/signed-inject.js";

const pao = parse(readFileSync("docs/core/agent-protocol.yaml", "utf8"), { maxAliasCount: -1 });
const SUBJECT = "секрет-предмет молоко";

const intent = (valid_to: string, over: Partial<MandateRequest> = {}): MandateRequest => ({
  type: "INTENT",
  subject: SUBJECT,
  amount_limit: 50_000,
  currency: "RUB",
  valid_to,
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
  ...over,
});

describe("verify и evidence по ПАО на стенде", () => {
  const code = "nspk:agent:evidence-a:v1";
  const otherCode = "nspk:agent:evidence-b:v1";
  let stand: Stand;
  let side: AgentSide;
  let other: AgentSide;
  const valid_to = new Date(Date.now() + 7 * 86_400_000).toISOString();

  beforeAll(() => {
    stand = createStand();
    side = newAgentSide();
    other = newAgentSide();
    expect(stand.admit(buyerApplication(code, side), "op").admitted).toBe(true);
    expect(stand.admit(buyerApplication(otherCode, other), "op").admitted).toBe(true);
  });
  afterAll(async () => stand.close());

  const create = async (req: MandateRequest): Promise<{ id: string; hash: string }> => {
    const res = await signedInject(stand.app, side, code, {
      method: "POST",
      path: "/pao/v1/mandates",
      body: JSON.stringify(req),
      headers: { "idempotency-key": randomUUID() },
    });
    expect(res.statusCode).toBe(201);
    return res.json() as { id: string; hash: string };
  };
  const get = (path: string, as: AgentSide = side, asCode = code) => signedInject(stand.app, as, asCode, { method: "GET", path });
  const cart = (parent_id: string): MandateRequest =>
    intent(valid_to, {
      type: "CART",
      parent_id,
      amount_limit: 1_000,
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk", qty: 1, price: 1_000 }], total: 1_000 },
    });

  it("verify: ровно {outcome, amount_left, valid_to, as_of} по схеме MandateVerify; предмета нет; исход по статусу", async () => {
    const m = await create(intent(valid_to));
    const pending = await get(`/pao/v1/mandates/${m.id}/verify`);
    expect(pending.statusCode).toBe(200);
    expect(Object.keys(pending.json()).sort()).toEqual(["amount_left", "as_of", "outcome", "valid_to"]);
    expect(Object.keys(pao.components.schemas.MandateVerify.properties).sort()).toEqual(["amount_left", "as_of", "outcome", "valid_to"]);
    expect(pending.json()).toMatchObject({ outcome: "OUT_OF_SCOPE", amount_left: 0, valid_to });
    expect(pending.body).not.toContain("молоко");
    await stand.issuer.sign(m.id);
    // До PS-09 остаток — предел (РП38 п. 6, ограничение).
    expect((await get(`/pao/v1/mandates/${m.id}/verify`)).json()).toMatchObject({ outcome: "CONFIRMED", amount_left: 50_000 });
    const k = await create(cart(m.id));
    await stand.issuer.sign(k.id);
    const cartVerify = await get(`/pao/v1/mandates/${k.id}/verify`);
    expect(cartVerify.json()).toMatchObject({ outcome: "CONFIRMED", amount_left: 1_000 });
    expect(cartVerify.body).not.toContain("milk");
    await stand.issuer.revoke(m.id);
    // CART — вместе с родителем (РП35 п. 2).
    expect((await get(`/pao/v1/mandates/${k.id}/verify`)).json()).toMatchObject({ outcome: "OUT_OF_SCOPE", amount_left: 0 });
    expect((await get(`/pao/v1/mandates/${m.id}/verify`)).json()).toMatchObject({ outcome: "OUT_OF_SCOPE" });
  });

  it("verify и evidence: чужой, неизвестный, не по форме id — 404 MANDATE_NOT_FOUND", async () => {
    const m = await create(intent(valid_to));
    for (const tail of ["verify", "evidence"]) {
      expect((await get(`/pao/v1/mandates/${m.id}/${tail}`, other, otherCode)).json()).toMatchObject({ code: "MANDATE_NOT_FOUND" });
      expect((await get(`/pao/v1/mandates/mnd_00000000-0000-4000-8000-000000000000/${tail}`)).statusCode).toBe(404);
      expect((await get(`/pao/v1/mandates/mnd_x/${tail}`)).statusCode).toBe(404);
    }
  });

  it("evidence: цепочка и подписи банка проверяются без Платформы; Mandate.hash — хэш записи; соли нет", async () => {
    const p = await create(intent(valid_to));
    await stand.issuer.sign(p.id);
    const k = await create(cart(p.id));
    await stand.issuer.sign(k.id);
    await stand.issuer.revoke(p.id);
    const res = await get(`/pao/v1/mandates/${k.id}/evidence`);
    expect(res.statusCode).toBe(200);
    const ev = res.json() as {
      mandate_chain: { id: string; hash: string; status: string; agent_code: string; revocation_order: string }[];
      records: JournalRecord[];
      operations: unknown[];
      integrity: string;
    };
    expect(ev.integrity).toBe("OK");
    expect(ev.operations).toEqual([]);
    for (const k2 of Object.keys(ev)) expect(Object.keys(pao.components.schemas.Evidence.properties)).toContain(k2);
    // Цепочка: CART — родитель и CART, статусы на момент чтения (РП35).
    expect(ev.mandate_chain.map((m) => [m.id, m.status])).toEqual([
      [p.id, "REVOKED"],
      [k.id, "REVOKED"],
    ]);
    expect(ev.mandate_chain.every((m) => m.agent_code === code && m.revocation_order !== undefined)).toBe(true);
    // Пересчёт без Платформы: начало — chainGenesis("consent:<корень>"), каждая запись — entryHash, связи prev_hash.
    let prev = chainGenesis(`consent:${ev.records[0]!.ref}`);
    for (const r of ev.records) {
      expect(r.prev_hash).toBe(prev);
      const { hash, ...rest } = r;
      expect(entryHash(rest)).toBe(hash);
      prev = hash;
    }
    for (const m of ev.mandate_chain) {
      expect(ev.records.find((r) => r.kind === "MANDATE_REQUESTED" && r.ref === m.id)?.hash).toBe(m.hash);
    }
    // Подписи банка — его открытым ключом (у проверяющего — из реестра участников).
    const bank = createPublicKey({ key: Buffer.from(stand.issuer.trustedKey.public_key, "base64"), format: "der", type: "spki" });
    const signedRecs = ev.records.filter((r) => r.kind === "MANDATE_SIGNED");
    expect(signedRecs).toHaveLength(2);
    for (const r of signedRecs) {
      const { signature, ...rec } = r.payload as unknown as MandateDecisionPayload;
      expect(edVerify(null, participantSigningInput(rec), bank, Buffer.from(signature, "base64url"))).toBe(true);
      expect(rec.mandate_hash).toBe(ev.records.find((x) => x.kind === "MANDATE_REQUESTED" && x.ref === r.ref)?.hash);
    }
    const rev = ev.records.find((r) => r.kind === "MANDATE_REVOKED")!;
    const { signature, ...revRec } = rev.payload as unknown as MandateRevocationPayload;
    expect(edVerify(null, participantRevocationSigningInput(revRec), bank, Buffer.from(signature, "base64url"))).toBe(true);
    // Соли нет; в записях — только обязательство предмета (предмет агента — в mandate_chain, как в GET).
    expect(res.body).not.toContain('"salt"');
    expect(ev.records.filter((r) => r.kind === "MANDATE_REQUESTED").every((r) => "subject_commitment" in (r.payload as object))).toBe(true);
    expect(JSON.stringify(ev.records)).not.toContain("молоко");
  });
});

describe("evidence: нарушенная цепочка — integrity BROKEN, 503 не даёт", () => {
  it("подмена записи в хранилище — BROKEN с пустыми массивами; verify — исключение (503 в ПАО)", async () => {
    const store = new MemoryConsentStore();
    const consent = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1" });
    const m = await consent.request("nspk:agent:broken:v1", "a".repeat(64), intent(new Date(Date.now() + 86_400_000).toISOString()));
    const row = (await store.getMandate(m.id!))!;
    await new AsyncHashChainJournal(store.journal(row.chain)).append("MANDATE_SIGNED", m.id!, {}, m.id!);
    const rows = (await store.journal(row.chain).all()) as unknown as object[];
    // Подмена payload записи решения в обход цепочки: хэш больше не сходится.
    rows[1] = { ...rows[1], payload: { forged: true } };
    expect(await consent.evidence(m.id!, "nspk:agent:broken:v1")).toEqual({ mandate_chain: [], records: [], operations: [], integrity: "BROKEN" });
    await expect(consent.verify(m.id!, "nspk:agent:broken:v1")).rejects.toThrow();
    expect(await consent.evidence(m.id!, "nspk:agent:other:v1")).toBeUndefined();
  });
});

describe("evidence: один снимок цепочки (РП35; `/audit` К2.6 № 1)", () => {
  it("отзыв родителя записан сразу после чтения цепочки — mandate_chain и records из одного снимка, без противоречия", async () => {
    const store = new MemoryConsentStore();
    const consent = new ConsentJournal(store, { revocationOrder: () => "bank:test:revocation:v1" });
    const agent = "nspk:agent:snapshot:v1";
    const valid_to = new Date(Date.now() + 86_400_000).toISOString();
    const p = await consent.request(agent, "b".repeat(64), intent(valid_to));
    const signOk = (id: string, hash: string) =>
      consent.sign(
        { participant_code: "p", kid: "k", mandate_id: id, mandate_hash: hash, decision: "SIGN", signature_type: "simple", signature_ref: "s", token_consent: true, signed_at: valid_to, signature: "x" },
        () => true,
        { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30 },
      );
    await signOk(p.id!, p.hash!);
    const k = await consent.request(agent, "c".repeat(64), intent(valid_to, {
      type: "CART",
      parent_id: p.id!,
      amount_limit: 1_000,
      cart: { merchant_id: "MER-1042", items: [{ sku: "milk", qty: 1, price: 1_000 }], total: 1_000 },
    }));
    await signOk(k.id!, k.hash!);
    // Одновременный отзыв: запись в цепочку сразу после первого чтения выписки.
    const chain = (await store.getMandate(p.id!))!.chain;
    const inner = store.journal(chain);
    let armed = true;
    const orig = store.journal.bind(store);
    store.journal = (c: string) =>
      c !== chain
        ? orig(c)
        : {
            genesis: inner.genesis,
            last: () => inner.last(),
            append: (e) => inner.append(e),
            all: async () => {
              // Снимок — копией, как у PostgreSQL; отзыв другого обработчика пишется сразу после чтения.
              const rows = [...(await inner.all())];
              if (armed) {
                armed = false;
                await new AsyncHashChainJournal(inner).append("MANDATE_REVOKED", p.id!, {}, p.id!);
              }
              return rows;
            },
          };
    const ev = (await consent.evidence(k.id!, agent))!;
    expect(ev.integrity).toBe("OK");
    const revokedInRecords = ev.records!.some((r) => r.kind === "MANDATE_REVOKED");
    expect(ev.mandate_chain!.map((m) => m.status)).toEqual(revokedInRecords ? ["REVOKED", "REVOKED"] : ["ACTIVE", "ACTIVE"]);
    expect(revokedInRecords).toBe(false);
    // Следующее чтение видит отзыв в обоих местах.
    const after = (await consent.evidence(k.id!, agent))!;
    expect(after.mandate_chain!.map((m) => m.status)).toEqual(["REVOKED", "REVOKED"]);
    expect(after.records!.some((r) => r.kind === "MANDATE_REVOKED")).toBe(true);
  });
});
