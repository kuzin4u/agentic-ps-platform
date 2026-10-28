// П1 УЦ песочницы (РП27 п. 1–2, РП65 п. 2): ключ ECDSA P-256, самоподписанный корневой сертификат, выпуск сертификата
// агента по CSR — один шаблон: пустой субъект, SAN — ровно один URI кода агента из записи реестра (не из CSR), CA:false,
// digitalSignature, clientAuth. Сертификат сервера Платформы — от того же УЦ (РП66 п. 4). notBefore — с запасом в прошлое
// (РП66 п. 5). Ключ УЦ — только в памяти процесса; файл с явной инициализацией — SEC-1-код ч. 2б (РП66 п. 6).
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { isIP } from "node:net";
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
const OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

/** Наибольший запас notBefore — граница cert_not_before_backdate_sec (РП66 п. 5). */
const BACKDATE_MAX_SEC = 3600;

/** Имя DNS сервера (РП66 п. 4, решение владельца 28.10 по В4): нижний регистр, без «*» и завершающей точки, до 253 знаков. */
const DNS_NAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Адрес IPv4 или IPv6 — байтами для iPAddress SAN (4 или 16); зона IPv6 («%eth0») — не адрес. */
function ipBytes(ip: string): Buffer | undefined {
  const v = ip.includes("%") ? 0 : isIP(ip);
  if (v === 4) return Buffer.from(ip.split(".").map(Number));
  if (v !== 6) return undefined;
  // Хвост IPv4 (::ffff:1.2.3.4) — две группы hex; затем «::» — недостающие нулевые группы.
  const tail = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  const hex = tail
    ? ip.slice(0, tail.index) + [Number(tail[1]) * 256 + Number(tail[2]), Number(tail[3]) * 256 + Number(tail[4])].map((g) => g.toString(16)).join(":")
    : ip;
  const [head = "", rest] = hex.split("::");
  const left = head === "" ? [] : head.split(":");
  const right = rest === undefined || rest === "" ? [] : rest.split(":");
  const groups = rest === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

/** SAN сервера: dNSName [2] или iPAddress [7]; имя не по правилу — исключение (ошибка развёртывания, не догадка). */
function serverName(name: string): Buffer {
  const ip = ipBytes(name);
  if (ip) return tlv(0x87, ip);
  if (!DNS_NAME.test(name)) throw new Error(`имя сервера не по правилу (DNS в нижнем регистре без точки в конце или IP): ${name}`);
  return tlv(0x82, Buffer.from(name, "ascii"));
}

/** Только коды песочницы (РП23 п. 1) по той же грамматике, что у реестра (РП21 п. 1): в SAN — urn: и код агента. */
export const isSandboxAgentCode = (code: string): boolean => {
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
  issueAgentCertificate(csr: unknown, agentCode: string, now: Date, ttlDays: number, backdateSec: number): IssueResult {
    if (!isSandboxAgentCode(agentCode)) throw new Error(`код агента не песочницы: ${agentCode}`);
    const { notBefore, notAfter } = this.validity(now, ttlDays, backdateSec);
    const parsed = parseCsr(csr);
    if (!parsed.ok) return parsed;
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

  /**
   * Сертификат сервера Платформы (РП66 п. 4): своя пара P-256 — только в памяти процесса, на диск не пишется; субъект
   * пуст, SAN критичное — имена DNS и адреса IP, serverAuth, digitalSignature, CA:false, SKI / AKI. Пустой список или имя
   * не по правилу — исключение.
   */
  issueServerCertificate(
    hostnames: readonly string[],
    now: Date,
    ttlDays: number,
    backdateSec: number,
  ): { readonly privateKey: KeyObject; readonly certificateDer: Buffer; readonly notBefore: Date; readonly notAfter: Date } {
    if (hostnames.length === 0) throw new Error("имена сервера: список пуст");
    const names = hostnames.map(serverName);
    const { notBefore, notAfter } = this.validity(now, ttlDays, backdateSec);
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const extensions = [
      extension(OID_SAN, true, seq(...names)),
      extension(OID_BASIC_CONSTRAINTS, true, seq()),
      extension(OID_KEY_USAGE, true, KU_DIGITAL_SIGNATURE),
      extension(OID_EXT_KEY_USAGE, false, seq(oid(OID_SERVER_AUTH))),
      extension(OID_SKI, false, octetString(keyIdentifier(publicKey))),
      extension(OID_AKI, false, seq(tlv(0x80, this.keyId))),
    ];
    const certificateDer = this.signTbs(newSerial(), EMPTY_NAME, notBefore, notAfter, publicKey, extensions);
    return { privateKey, certificateDer, notBefore, notAfter };
  }

  /**
   * Срок выдаваемого сертификата (РП65 п. 2, РП66 п. 5): часы Платформы — в сроке УЦ; notBefore = max(notBefore УЦ,
   * часы − запас) — клиент с отстающими часами не отвергнет новый сертификат; notAfter = min(часы + срок, notAfter УЦ).
   * Неверные аргументы и УЦ вне срока — исключение: ошибка вызывающего, а не заявления (инвариант 3).
   */
  private validity(now: Date, ttlDays: number, backdateSec: number): { notBefore: Date; notAfter: Date } {
    if (!Number.isInteger(ttlDays) || ttlDays < 1) throw new Error("срок сертификата: целое ≥ 1");
    if (!Number.isInteger(backdateSec) || backdateSec < 0 || backdateSec > BACKDATE_MAX_SEC) {
      throw new Error(`запас notBefore: целое 0…${BACKDATE_MAX_SEC}`);
    }
    // Неразбираемое время — до сравнения сроков: сравнения с NaN ложны, проверка срока УЦ прошла бы.
    if (!Number.isFinite(now.getTime())) throw new Error("время выпуска не разбирается");
    const issued = toSecond(now).getTime();
    if (issued < this.notBefore.getTime() || issued >= this.notAfter.getTime()) throw new Error("УЦ песочницы вне срока действия");
    return {
      notBefore: new Date(Math.max(this.notBefore.getTime(), issued - backdateSec * 1000)),
      notAfter: new Date(Math.min(issued + ttlDays * DAY_MS, this.notAfter.getTime())),
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
