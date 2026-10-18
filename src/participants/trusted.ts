// П10 Доверенные ключи участников до шлюза участников (РП36 п. 4; PS-20 расширит): подпись банка над хэшем мандата.
// Ключей и данных входа клиентов у Платформы нет — только открытые ключи банков (РП36 п. 3, 5).
// Fail-closed: файл задан, но не читается или неверен — отказ запуска; списка нет или он пуст — подпись отклоняется всем.
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalJson } from "@kuzin4u/agentic-core";
import type { MandateDecisionPayload } from "../consent/model.js";
import { ED25519, parseKey } from "../registry/keys.js";

/** Метка контекста подписи участника (РП36 доп.): подпись банка пригодна только для подписи мандата этой версии. */
export const PARTICIPANT_SIGNATURE_CONTEXT = "pao:participant-mandate-signature:v1";

/** Код эмулятора эмитента стенда: ключ создаётся при старте стенда и только в памяти; в рабочем сервере — отказ запуска. */
export const STAND_ISSUER_CODE = "stand:issuer-emulator";

/**
 * Не больше одного боевого участника (эмулятор стенда не считается), пока мандат не привязан к банку (РП36 доп.):
 * иначе банк Б подписал бы мандат клиента банка А. Привязка — Б2, вместе с форматом principal_ref.
 */
export const MAX_LIVE_PARTICIPANTS = 1;

const PARTICIPANT_CODE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$/;

export interface TrustedParticipantKey {
  readonly participant_code: string;
  readonly kid: string;
  readonly alg: string;
  /** DER SPKI, каноническая запись base64 (как у агентов, РП23 доп. 6). */
  readonly public_key: string;
}

export interface TrustedParticipantsOptions {
  /** Стенд (РП25): разрешён ключ эмулятора эмитента. В рабочем сервере — false. */
  readonly stand: boolean;
}

export class TrustedParticipants {
  private readonly keys = new Map<string, KeyObject>();

  constructor(list: readonly TrustedParticipantKey[], opts: TrustedParticipantsOptions) {
    const live = new Set<string>();
    for (const k of list) {
      if (typeof k.participant_code !== "string" || !PARTICIPANT_CODE.test(k.participant_code)) {
        throw new Error(`Доверенные участники: недопустимый participant_code «${String(k.participant_code)}»`);
      }
      if (k.participant_code === STAND_ISSUER_CODE) {
        if (!opts.stand) {
          throw new Error(`Доверенные участники: ключ эмулятора ${STAND_ISSUER_CODE} допустим только на стенде (РП36 доп.)`);
        }
      } else {
        live.add(k.participant_code);
      }
      // Тот же разбор, что у ключей агентов: каноническая запись, ed25519, слабые ключи — отказ.
      const parsed = parseKey([ED25519], k.alg, k.public_key);
      if (!parsed) throw new Error(`Доверенные участники: ключ ${k.participant_code}/${String(k.kid)} не принят (ed25519, DER SPKI base64)`);
      if (parsed.kid !== k.kid) throw new Error(`Доверенные участники: kid ${String(k.kid)} ≠ отпечатку RFC 7638 ключа ${k.participant_code}`);
      const id = keyId(k.participant_code, k.kid);
      if (this.keys.has(id)) throw new Error(`Доверенные участники: ключ ${id} указан дважды`);
      this.keys.set(id, createPublicKey({ key: Buffer.from(k.public_key, "base64"), format: "der", type: "spki" }));
    }
    if (live.size > MAX_LIVE_PARTICIPANTS) {
      throw new Error(
        `Доверенные участники: ${live.size} боевых участника (${[...live].join(", ")}) — до привязки мандата к банку ` +
          `(Б2, формат principal_ref) допустим не больше ${MAX_LIVE_PARTICIPANTS} (РП36 доп.); второй банк — решение владельца`,
      );
    }
  }

  /** Подпись участника над записью; неизвестный участник или ключ — false, как неверная подпись. */
  verify(participant_code: string, kid: string, record: ParticipantSignedRecord, signature: string): boolean {
    const key = this.keys.get(keyId(participant_code, kid));
    if (!key) return false;
    const sig = Buffer.from(signature, "base64url");
    if (sig.length !== 64 || sig.toString("base64url") !== signature) return false;
    return verify(null, participantSigningInput(record), key, sig);
  }
}

const keyId = (participant_code: string, kid: string): string => `${participant_code}\n${kid}`;

/** Подписываемая участником запись о решении клиента (РП36 доп.); метка контекста добавляется при подписи. */
export type ParticipantSignedRecord = Omit<MandateDecisionPayload, "signature">;

/** Байты подписи: canonicalJson записи с меткой контекста, UTF-8. */
export const participantSigningInput = (r: ParticipantSignedRecord): Buffer =>
  Buffer.from(
    canonicalJson({
      context: PARTICIPANT_SIGNATURE_CONTEXT,
      participant_code: r.participant_code,
      kid: r.kid,
      mandate_id: r.mandate_id,
      mandate_hash: r.mandate_hash,
      decision: r.decision,
      signature_type: r.signature_type,
      signature_ref: r.signature_ref,
      token_consent: r.token_consent,
      signed_at: r.signed_at,
    }),
    "utf8",
  );

/**
 * Список доверенных ключей из файла PARTICIPANT_KEYS_PATH: `{"participants": [{participant_code, kid, alg, public_key}]}`.
 * Пути нет — пустой список (подпись отклоняется всем). Файл не читается, не JSON, лишние поля — отказ запуска.
 */
export function loadTrustedParticipants(path: string | undefined, opts: TrustedParticipantsOptions): TrustedParticipants {
  if (path === undefined || path === "") return new TrustedParticipants([], opts);
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`PARTICIPANT_KEYS_PATH=${path}: файл не читается или не JSON (${(err as Error).message})`);
  }
  const list = (doc as { participants?: unknown } | null)?.participants;
  if (!Array.isArray(list) || Object.keys(doc as object).length !== 1) {
    throw new Error(`PARTICIPANT_KEYS_PATH=${path}: ожидается {"participants": [...]}`);
  }
  for (const k of list) {
    const fields = k !== null && typeof k === "object" ? Object.keys(k).sort().join(",") : "";
    if (fields !== "alg,kid,participant_code,public_key") {
      throw new Error(`PARTICIPANT_KEYS_PATH=${path}: запись — ровно participant_code, kid, alg, public_key`);
    }
  }
  return new TrustedParticipants(list as TrustedParticipantKey[], opts);
}
