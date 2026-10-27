// П1 Разбор CSR оператора агента (РП65 п. 1–2): PKCS#10 в DER, каноническая base64, один шаблон — ключ P-256,
// подпись ecdsa-with-SHA256 ключом из самого CSR. Субъект и атрибуты проверяются только как DER и не читаются:
// в сертификат из CSR переходит один открытый ключ (инвариант 5).
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { bytesOf, children, contentOf, DerError, parseStrict, type Tlv } from "./der.js";

/** Предел CSR в DER и длина его записи base64 (РП65 п. 2). */
export const CSR_MAX_DER_BYTES = 2048;
export const CSR_MAX_BASE64_CHARS = Math.ceil(CSR_MAX_DER_BYTES / 3) * 4;

/** Вид причины отказа — только в журнал процесса; оператору — KEY_INVALID (РП65 п. 1, РП31 п. 2). */
export type CsrRejection = "FORMAT" | "TOO_LONG" | "DER" | "TEMPLATE" | "KEY" | "SIGNATURE";

export type CsrParseResult =
  | { readonly ok: true; readonly publicKey: KeyObject; readonly spki: Buffer }
  | { readonly ok: false; readonly reason: CsrRejection };

/** SubjectPublicKeyInfo P-256 до точки: id-ecPublicKey, prime256v1, BIT STRING из 66 байт (0x00 и несжатая точка). */
export const P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
const P256_SPKI_BYTES = P256_SPKI_PREFIX.length + 65;
/** AlgorithmIdentifier ecdsa-with-SHA256 без параметров (RFC 5758 §3.2). */
export const ECDSA_SHA256 = Buffer.from("300a06082a8648ce3d040302", "hex");
/** version INTEGER 0. */
const VERSION_0 = Buffer.from("020100", "hex");

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

export function parseCsr(input: unknown): CsrParseResult {
  if (typeof input !== "string" || input === "") return { ok: false, reason: "FORMAT" };
  // Длина строки — до декодирования: длинная строка не декодируется вовсе.
  if (input.length > CSR_MAX_BASE64_CHARS) return { ok: false, reason: "TOO_LONG" };
  if (input.length % 4 !== 0 || !BASE64.test(input)) return { ok: false, reason: "FORMAT" };
  const der = Buffer.from(input, "base64");
  // Каноническая запись: строка совпадает с повторным кодированием своих байтов (РП23 доп. 6).
  if (der.toString("base64") !== input) return { ok: false, reason: "FORMAT" };
  if (der.length > CSR_MAX_DER_BYTES) return { ok: false, reason: "TOO_LONG" };

  let info: Buffer;
  let spki: Buffer;
  let signature: Buffer;
  try {
    const root = parseStrict(der);
    if (root.tag !== 0x30) return { ok: false, reason: "TEMPLATE" };
    const top = children(der, root);
    if (top.length !== 3) return { ok: false, reason: "TEMPLATE" };
    const [cri, alg, sig] = top as [Tlv, Tlv, Tlv];
    if (cri.tag !== 0x30 || !bytesOf(der, alg).equals(ECDSA_SHA256) || sig.tag !== 0x03) return { ok: false, reason: "TEMPLATE" };
    const parts = children(der, cri);
    // version, subject, subjectPKInfo, attributes [0] IMPLICIT SET — все четыре обязательны (RFC 2986 §4.1).
    if (parts.length !== 4) return { ok: false, reason: "TEMPLATE" };
    const [version, subject, pki, attrs] = parts as [Tlv, Tlv, Tlv, Tlv];
    if (!bytesOf(der, version).equals(VERSION_0) || subject.tag !== 0x30 || attrs.tag !== 0xa0) {
      return { ok: false, reason: "TEMPLATE" };
    }
    spki = bytesOf(der, pki);
    if (spki.length !== P256_SPKI_BYTES || !spki.subarray(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) {
      return { ok: false, reason: "TEMPLATE" };
    }
    if (spki[P256_SPKI_PREFIX.length] !== 0x04) return { ok: false, reason: "TEMPLATE" };
    const bits = contentOf(der, sig);
    if (bits.length < 2 || bits[0] !== 0x00) return { ok: false, reason: "TEMPLATE" };
    info = bytesOf(der, cri);
    signature = bits.subarray(1);
  } catch (e) {
    if (e instanceof DerError) return { ok: false, reason: "DER" };
    throw e;
  }

  // Точка на кривой — разбор ключа node:crypto (OpenSSL); не на кривой — отказ.
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
  } catch {
    return { ok: false, reason: "KEY" };
  }
  // Владение ключом: CSR подписан закрытым ключом, парным открытому из него.
  let valid: boolean;
  try {
    valid = verify("sha256", info, { key: publicKey, dsaEncoding: "der" }, signature);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "SIGNATURE" };
  return { ok: true, publicKey, spki };
}
