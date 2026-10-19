// П3 + П2 для тестов (PS-09 К1.3, К1.5): журнал согласий в памяти, StateService на удержаниях ядра, ПИ-8 с эмулятором
// эмитента — подключение то же, что в рабочем сервере (остаток verify из П3, MANDATE_EXHAUSTED от П3).
import { createHash, randomUUID } from "node:crypto";
import { AsyncMemoryHoldLedger, type AsyncHoldLedger } from "@kuzin4u/agentic-core";
import type { FastifyInstance } from "fastify";
import { ConsentJournal } from "../../src/consent/journal.js";
import { MemoryConsentStore, type ConsentStore } from "../../src/consent/store.js";
import type { MandateExhaustedPayload } from "../../src/consent/model.js";
import { createIssuerEmulator, type IssuerEmulator } from "../../src/env/issuer/index.js";
import { TrustedParticipants, type ParticipantSignedRecord } from "../../src/participants/trusted.js";
import { buildServer } from "../../src/server.js";
import type { MandateRequest } from "../../src/shared/pao.js";
import { StateService } from "../../src/state/index.js";

export const A = "nspk:agent:state-a:v1";
export const T0 = new Date("2026-10-19T10:00:00Z");
const POLICY = { qualified_signature_above_kop: 5_000_000, qualified_signature_above_days: 30, unavailable_retry_after_sec: 1 };
const key = (): string => createHash("sha256").update(randomUUID()).digest("hex");

export const intent = (over: Partial<MandateRequest> = {}): MandateRequest => ({
  type: "INTENT",
  subject: "молоко 2 л",
  amount_limit: 50_000,
  currency: "RUB",
  valid_to: "2026-10-24T10:00:00Z",
  merchant_scope: ["MER-1042"],
  principal_ref: "prn_7f3c9a",
  mode: "IMMEDIATE",
  ...over,
});

export interface Ctx {
  consent: ConsentJournal;
  ledger: AsyncHoldLedger;
  state: StateService;
  app: FastifyInstance;
  emu: IssuerEmulator;
}

export function setup(
  opts: {
    ledger?: AsyncHoldLedger;
    store?: ConsentStore;
    exhausted?: (id: string, p: MandateExhaustedPayload) => Promise<unknown>;
    log?: (msg: string) => void;
  } = {},
): Ctx {
  const consent: ConsentJournal = new ConsentJournal(opts.store ?? new MemoryConsentStore(), {
    revocationOrder: () => "bank:test:revocation:v1",
    now: () => T0,
    amountLeft: (id, limit) => state.amountLeft(id, limit),
  });
  const ledger = opts.ledger ?? new AsyncMemoryHoldLedger();
  const state: StateService = new StateService(ledger, consent, {
    reservationTtlSec: 600,
    now: () => T0,
    exhausted: opts.exhausted ?? ((id, p) => consent.exhausted(id, p)),
    log: (_l, _f, msg) => opts.log?.(msg),
  });
  const emu = createIssuerEmulator();
  const trusted = new TrustedParticipants([emu.trustedKey], { stand: true });
  const app = buildServer({ env: "dev", participants: { trusted, consent, params: POLICY, state } });
  return { consent, ledger, state, app, emu };
}

export async function mk(c: Ctx, req: MandateRequest = intent()): Promise<{ id: string; hash: string }> {
  const m = await c.consent.request(A, key(), req);
  if (!m.id || !m.hash) throw new Error("нет id или hash");
  return { id: m.id, hash: m.hash };
}

export async function decide(c: Ctx, m: { id: string; hash: string }, decision: "SIGN" | "REJECT" = "SIGN"): Promise<number> {
  const r: ParticipantSignedRecord = {
    participant_code: c.emu.participant_code,
    kid: c.emu.trustedKey.kid,
    mandate_id: m.id,
    mandate_hash: m.hash,
    decision,
    signature_type: "simple",
    signature_ref: `sig-${m.id.slice(-6)}`,
    token_consent: true,
    signed_at: T0.toISOString(),
  };
  const { mandate_id: _id, ...rest } = r;
  void _id;
  const res = await c.app.inject({
    method: "POST",
    url: `/participants/v1/mandates/${m.id}/sign`,
    payload: { ...rest, signature: c.emu.signRecord(r) },
  });
  return res.statusCode;
}

export async function revoke(c: Ctx, m: { id: string; hash: string }): Promise<number> {
  const record = {
    participant_code: c.emu.participant_code,
    kid: c.emu.trustedKey.kid,
    mandate_id: m.id,
    mandate_hash: m.hash,
    revocation_ref: `rev-${m.id.slice(-6)}`,
    revoked_at: T0.toISOString(),
  };
  const { mandate_id: _id, ...body } = { ...record, signature: c.emu.signRevocation(record) };
  void _id;
  const res = await c.app.inject({ method: "POST", url: `/participants/v1/mandates/${m.id}/revoke`, payload: body });
  return res.statusCode;
}
