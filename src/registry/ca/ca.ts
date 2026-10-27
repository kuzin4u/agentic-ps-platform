// П1 УЦ песочницы (РП27 п. 1–2, РП65 п. 2): ключ ECDSA P-256, самоподписанный корневой сертификат, выпуск сертификата
// агента по CSR — один шаблон: пустой субъект, SAN — ровно один URI кода агента из записи реестра (не из CSR), CA:false,
// digitalSignature, clientAuth. Ключ УЦ в ч. 1 — только в памяти процесса; файл на постоянном томе — SEC-1-код ч. 2 (п. 4).
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { AgentCodeError, parseAgentCode, REGISTRY_ISSUER } from "../code.js";
import { parseCsr, ECDSA_SHA256, P256_SPKI_PREFIX, type CsrRejection } from "./csr.js";
import { BOOLEAN_TRUE, bitString, explicit, octetString, oid, seq, set, time, tlv, uint, utf8 } from "./der.js";

const DAY_MS = 86_400_000;

/** Имя УЦ в issuer сертификатов агентов. */
export const SANDBOX_CA_NAME = "agentic-ps-platform sandbox CA";

const OID_CN = "2.5.4.3";
const OID_SAN = "2.5.29.17";
const OID_SKI = "2.5.29.14";
const OID_AKI = "2.5.29.35";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

/** Только коды песочницы (РП23 п. 1) по той же грамматике, что у реестра (РП21 п. 1): в SAN — urn: и код агента. */
const isSandboxAgentCode = (code: string): boolean => {
  try {
    return parseAgentCode(code).issuer === REGISTRY_ISSUER;
  } catch (e) {
    if (e instanceof AgentCodeError) return false;
    throw e;
  }
};

/**
 * keyIdentifier по методу 1 RFC 5280 §4.2.1.2 (РП65 нюанс 4): SHA-1 от значения BIT STRING subjectPublicKey — для P-256
 * это несжатая точка, 65 байт после префикса SPKI.
 */
const keyIdentifier = (key: KeyObject): Buffer => {
  const spki = key.export({ format: "der", type: "spki" });
  return createHash("sha1").update(spki.subarray(P256_SPKI_PREFIX.length)).digest();
};

/** Расширение: критичность пишется только при true (DER, DEFAULT FALSE). */
const extension = (id: string, critical: boolean, value: Buffer): Buffer =>
  seq(oid(id), ...(critical ? [BOOLEAN_TRUE] : []), octetString(value));

const name = (cn: string): Buffer => seq(set(seq(oid(OID_CN), utf8(cn))));
const EMPTY_NAME = seq();

/** keyUsage: digitalSignature (бит 0) и keyCertSign (бит 5) — именованная битовая строка в кратчайшей записи. */
const KU_DIGITAL_SIGNATURE = bitString(Buffer.from([0x80]), 7);
const KU_KEY_CERT_SIGN = bitString(Buffer.from([0x04]), 2);

/** Секунды без долей: в сертификате время — с точностью до секунды, в записи реестра — то же значение. */
const toSecond = (d: Date): Date => new Date(Math.floor(d.getTime() / 1000) * 1000);

/** Серийный номер (РП65 п. 2): 16 случайных байт, положительный и в кратчайшей записи — старшие биты 01. */
const newSerial = (): Buffer => {
  const b = randomBytes(16);
  b[0] = (b[0]! & 0x3f) | 0x40;
  return b;
};

/** Сертификат агента в решении о допуске и в записи реестра (РП65 п. 3). */
export interface AgentCertificate {
  /** Серийный номер, hex в нижнем регистре. */
  readonly serial: string;
  /** Сертификат, DER в канонической base64. */
  readonly der: string;
  readonly not_before: string;
  readonly not_after: string;
}

export type IssueResult =
  | { readonly ok: true; readonly certificate: AgentCertificate }
  | { readonly ok: false; readonly reason: CsrRejection };

export interface SandboxCaOptions {
  readonly now: Date;
  /** Срок корневого сертификата — sandbox_ca_ttl_days (РП65 п. 5). */
  readonly ttlDays: number;
}

export class SandboxCa {
  /** Корневой сертификат УЦ, DER. */
  readonly certificateDer: Buffer;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly publicKey: KeyObject;
  /** subjectKeyIdentifier корневого — keyIdentifier в AKI сертификатов агентов (РП65 нюанс 4). */
  readonly keyId: Buffer;

  private constructor(
    private readonly privateKey: KeyObject,
    publicKey: KeyObject,
    opts: SandboxCaOptions,
  ) {
    if (!Number.isInteger(opts.ttlDays) || opts.ttlDays < 1) throw new Error("срок УЦ: целое ≥ 1");
    this.publicKey = publicKey;
    this.notBefore = toSecond(opts.now);
    this.notAfter = new Date(this.notBefore.getTime() + opts.ttlDays * DAY_MS);
    this.keyId = keyIdentifier(publicKey);
    const extensions = [
      extension(OID_BASIC_CONSTRAINTS, true, seq(BOOLEAN_TRUE, uint(Buffer.from([0])))),
      extension(OID_KEY_USAGE, true, KU_KEY_CERT_SIGN),
      extension(OID_SKI, false, octetString(this.keyId)),
    ];
    this.certificateDer = this.signTbs(newSerial(), name(SANDBOX_CA_NAME), this.notBefore, this.notAfter, publicKey, extensions);
  }

  /** Новая пара P-256 и корневой сертификат (ч. 1 — в памяти; загрузка из файла — ч. 2). */
  static generate(opts: SandboxCaOptions): SandboxCa {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    return new SandboxCa(privateKey, publicKey, opts);
  }

  /**
   * Сертификат агента по CSR (РП65 п. 2). CSR не по шаблону — отказ с видом причины (оператору — KEY_INVALID). Код агента
   * не по грамматике песочницы и истёкший УЦ — исключение: это ошибка вызывающего, а не заявления (инвариант 3).
   */
  issueAgentCertificate(csr: unknown, agentCode: string, now: Date, ttlDays: number): IssueResult {
    if (!isSandboxAgentCode(agentCode)) throw new Error(`код агента не песочницы: ${agentCode}`);
    if (!Number.isInteger(ttlDays) || ttlDays < 1) throw new Error("срок сертификата: целое ≥ 1");
    // Неразбираемое время — до сравнения сроков: сравнения с NaN ложны, проверка срока УЦ прошла бы.
    if (!Number.isFinite(now.getTime())) throw new Error("время выпуска не разбирается");
    const parsed = parseCsr(csr);
    if (!parsed.ok) return parsed;
    const notBefore = toSecond(now);
    if (notBefore.getTime() < this.notBefore.getTime() || notBefore.getTime() >= this.notAfter.getTime()) {
      throw new Error("УЦ песочницы вне срока действия");
    }
    const notAfter = new Date(Math.min(notBefore.getTime() + ttlDays * DAY_MS, this.notAfter.getTime()));
    const serial = newSerial();
    const extensions = [
      // Субъект пуст — SAN критичное (RFC 5280 §4.2.1.6); [6] IMPLICIT IA5String — URI.
      extension(OID_SAN, true, seq(tlv(0x86, Buffer.from(`urn:${agentCode}`, "ascii")))),
      extension(OID_BASIC_CONSTRAINTS, true, seq()),
      extension(OID_KEY_USAGE, true, KU_DIGITAL_SIGNATURE),
      extension(OID_EXT_KEY_USAGE, false, seq(oid(OID_CLIENT_AUTH))),
      // AKI — только keyIdentifier [0] IMPLICIT (РП65 нюанс 4).
      extension(OID_AKI, false, seq(tlv(0x80, this.keyId))),
    ];
    const der = this.signTbs(serial, EMPTY_NAME, notBefore, notAfter, parsed.publicKey, extensions);
    return {
      ok: true,
      certificate: {
        serial: serial.toString("hex"),
        der: der.toString("base64"),
        not_before: notBefore.toISOString(),
        not_after: notAfter.toISOString(),
      },
    };
  }

  /** Отпечаток корневого сертификата (SHA-256, hex) — для журнала процесса и проверки, что УЦ тот же. */
  get fingerprint(): string {
    return createHash("sha256").update(this.certificateDer).digest("hex");
  }

  private signTbs(
    serial: Buffer,
    subject: Buffer,
    notBefore: Date,
    notAfter: Date,
    subjectKey: KeyObject,
    extensions: readonly Buffer[],
  ): Buffer {
    const tbs = seq(
      explicit(0, uint(Buffer.from([2]))),
      uint(serial),
      ECDSA_SHA256,
      name(SANDBOX_CA_NAME),
      seq(time(notBefore), time(notAfter)),
      subject,
      subjectKey.export({ format: "der", type: "spki" }),
      explicit(3, seq(...extensions)),
    );
    const signature = sign("sha256", tbs, { key: this.privateKey, dsaEncoding: "der" });
    return seq(tbs, ECDSA_SHA256, bitString(signature));
  }
}
