// Тестовый банк-участник (Р-1031, Р-1040, К1.2 сессии 61): подпись и отзыв мандата по ПИ-8 —
// POST /participants/v1/mandates/{id}/sign и …/revoke по HTTPS. Доверие — только к корню УЦ песочницы (--ca), отпечаток
// корня сверяется до соединения (как у acceptance); имя сервера — по сертификату. Подпись — теми же функциями, что
// проверяет сервер (participantSigningInput, participantRevocationSigningInput), с метками РП36 доп. и РП38 п. 1.
// Mandate.hash банк берёт у агента (GET /pao/v1/mandates/{id}): чтения мандата банком в ПИ-8 нет (STATUS «Открыто»).
import { createPrivateKey, createPublicKey, randomBytes, sign, X509Certificate, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:https";
import { isIP } from "node:net";
import { normFingerprint } from "../acceptance/checks.js";
import { isOpaquePrincipalRef } from "../../src/consent/terms.js";
import {
  participantRevocationSigningInput,
  participantSigningInput,
  type ParticipantRevocationRecord,
  type ParticipantSignedRecord,
} from "../../src/participants/trusted.js";
import { ED25519, parseKey } from "../../src/registry/keys.js";
import { ParticipantToolError } from "./keys.js";

export interface Target {
  readonly host: string;
  readonly port: number;
  /** Корневой сертификат УЦ песочницы, PEM (вывод ca:init). */
  readonly caPem: string;
  /** Ожидаемый отпечаток SHA-256 корня: hex, регистр и двоеточия не важны. */
  readonly fingerprint: string;
}

export interface BankKey {
  readonly participant_code: string;
  readonly kid: string;
  readonly privateKey: KeyObject;
}

export interface Reply {
  readonly status: number;
  readonly body: unknown;
}

/** Ключ банка из файла keygen; kid — отпечаток RFC 7638 открытой части, как в participants.json. */
export function loadBankKey(path: string, participant_code: string): BankKey {
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(readFileSync(path));
  } catch (e) {
    throw new ParticipantToolError("KEY_INVALID", `ключ не прочитан: ${(e as NodeJS.ErrnoException).code ?? "не PEM"}`);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new ParticipantToolError("KEY_INVALID", "ключ не ed25519");
  const public_key = createPublicKey(privateKey).export({ type: "spki", format: "der" }).toString("base64");
  const parsed = parseKey([ED25519], "ed25519", public_key);
  if (!parsed) throw new ParticipantToolError("KEY_INVALID", "ключ ed25519 не разобран");
  return { participant_code, kid: parsed.kid, privateKey };
}

/** Корень — сертификат PEM с отпечатком SHA-256, равным ожидаемому; иначе отказ до соединения. */
export function checkRoot(caPem: string, fingerprint: string): void {
  let fp: string;
  try {
    fp = normFingerprint(new X509Certificate(caPem).fingerprint256);
  } catch {
    throw new ParticipantToolError("CA_INVALID", "корень — не сертификат PEM");
  }
  if (fp !== normFingerprint(fingerprint)) throw new ParticipantToolError("FINGERPRINT_MISMATCH", "отпечаток корня ≠ --fingerprint");
}

/**
 * Непрозрачная ссылка банка (signature_ref, revocation_ref): base64url без 7 цифр подряд — иначе isOpaquePrincipalRef
 * сервера отклонит её (400) как похожую на телефон или СНИЛС (РП38 п. 7).
 */
export function opaqueRef(prefix: string, random: () => Buffer = () => randomBytes(12)): string {
  for (;;) {
    const ref = `${prefix}-${random().toString("base64url")}`;
    if (isOpaquePrincipalRef(ref)) return ref;
  }
}

const HASH = /^[0-9a-f]{64}$/;

function post(t: Target, path: string, body: Record<string, unknown>, timeoutMs: number): Promise<Reply> {
  checkRoot(t.caPem, t.fingerprint);
  const data = Buffer.from(JSON.stringify(body), "utf8");
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: t.host,
        port: t.port,
        path,
        method: "POST",
        headers: { "content-type": "application/json", "content-length": String(data.length) },
        // Только корень песочницы: системные корни не доверяются; имя сервера — по сертификату (SNI и проверка имени).
        ca: t.caPem,
        ...(isIP(t.host) === 0 ? { servername: t.host } : {}),
        minVersion: "TLSv1.3",
        agent: false,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: unknown = text;
          try {
            parsed = JSON.parse(text);
          } catch {
            // тело не JSON — отдаём как есть
          }
          resolve({ status: res.statusCode ?? 0, body: parsed });
        });
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "TIMEOUT" })));
    req.on("error", (e: NodeJS.ErrnoException) => reject(new ParticipantToolError("CONNECT_FAILED", e.code ?? e.name)));
    req.end(data);
  });
}

const mandatePath = (id: string, action: "sign" | "revoke") => `/participants/v1/mandates/${encodeURIComponent(id)}/${action}`;

export interface SignInput {
  readonly mandate_id: string;
  readonly mandate_hash: string;
  readonly decision: "SIGN" | "REJECT";
  readonly signature_type: "simple" | "qualified" | "gov_id";
  readonly token_consent: boolean;
}

/** Решение клиента по мандату (РП36 доп.): запись → подпись с меткой pao:participant-mandate-signature:v1 → ПИ-8. */
export async function signMandate(t: Target, key: BankKey, input: SignInput, o: { now?: Date; timeoutMs?: number } = {}): Promise<Reply> {
  if (!HASH.test(input.mandate_hash)) throw new ParticipantToolError("ARGS_INVALID", "--hash — 64 hex в нижнем регистре (Mandate.hash)");
  const record: ParticipantSignedRecord = {
    participant_code: key.participant_code,
    kid: key.kid,
    mandate_id: input.mandate_id,
    mandate_hash: input.mandate_hash,
    decision: input.decision,
    signature_type: input.signature_type,
    signature_ref: opaqueRef("sig"),
    token_consent: input.token_consent,
    signed_at: (o.now ?? new Date()).toISOString(),
  };
  const signature = sign(null, participantSigningInput(record), key.privateKey).toString("base64url");
  const { mandate_id: _id, ...body } = record;
  void _id;
  return post(t, mandatePath(input.mandate_id, "sign"), { ...body, signature }, o.timeoutMs ?? 10_000);
}

/** Отзыв клиентом (РП38 п. 1): запись → подпись с меткой pao:participant-mandate-revocation:v1 → ПИ-8. */
export async function revokeMandate(
  t: Target,
  key: BankKey,
  input: { readonly mandate_id: string; readonly mandate_hash: string },
  o: { now?: Date; timeoutMs?: number } = {},
): Promise<Reply> {
  if (!HASH.test(input.mandate_hash)) throw new ParticipantToolError("ARGS_INVALID", "--hash — 64 hex в нижнем регистре (Mandate.hash)");
  const record: ParticipantRevocationRecord = {
    participant_code: key.participant_code,
    kid: key.kid,
    mandate_id: input.mandate_id,
    mandate_hash: input.mandate_hash,
    revocation_ref: opaqueRef("rev"),
    revoked_at: (o.now ?? new Date()).toISOString(),
  };
  const signature = sign(null, participantRevocationSigningInput(record), key.privateKey).toString("base64url");
  const { mandate_id: _id, ...body } = record;
  void _id;
  return post(t, mandatePath(input.mandate_id, "revoke"), { ...body, signature }, o.timeoutMs ?? 10_000);
}
