// П9 Ступень 0 проверки обращения ПАО — сертификат канала mTLS (РП27 п. 3, РП66 п. 1–2): своя проверка DER из соединения
// по часам Платформы в дополнение к флагу TLS authorized (тот смотрит системные часы; РП66 нюанс К3 п. 2). Любой отказ —
// AGENT_UNKNOWN: сертификат канала перевыпускает оператор агента, а AGENT_KEY_REVOKED (new_key) вёл бы агента к ротации
// ключа подписи (РП66 п. 2). Вид причины — только в журнал процесса (РП31 п. 2). Сбой чтения реестра — UPSTREAM_UNAVAILABLE
// (РП23 доп. 4).
import { X509Certificate } from "node:crypto";
import { isSandboxAgentCode } from "../registry/ca/ca.js";
import type { AgentCertificateRecord } from "../registry/model.js";

/** Вид причины отказа ступени 0 — шаги РП66 п. 1 по порядку. */
export type ChannelReject =
  | "NO_CERTIFICATE"
  /** TLS не подтвердил цепочку к доверенному УЦ (socket.authorized !== true; дополнение чата 1, решение владельца 28.10). */
  | "TLS_NOT_AUTHORIZED"
  | "NOT_ISSUED_BY_CA"
  | "SUBJECT_NOT_AGENT"
  | "NOT_IN_REGISTRY"
  | "CODE_MISMATCH"
  | "OUTSIDE_VALIDITY"
  | "REVOKED"
  /** Исключение самой проверки (не источника) — отказ, а не 500 из хука (КТ1 № 4). */
  | "CHECK_FAILED";

export interface ChannelOptions {
  /** Корневой сертификат УЦ песочницы — единственный доверенный (РП66 п. 3). */
  readonly ca: X509Certificate;
  /** Запись сертификата в реестре по серийному номеру — на каждом обращении, без кэша (РП64 п. 3, РП65 п. 3). */
  getCertificate(serial: string): Promise<AgentCertificateRecord | undefined>;
  /**
   * revocation_propagation_max_ms: отметка предпроверки (verify.ts) старше этого по часам Платформы не принимается — ступень 0
   * заново; окно «отзыв во время чтения тела» ограничено временем распространения отзыва (инвариант 8; РП66 нюанс К3 п. 5).
   */
  readonly ticketMaxAgeMs: number;
}

/** Сертификат клиента из TLS-соединения: DER и итог проверки цепочки TLS (socket.authorized). */
export interface ClientCertificate {
  readonly der: Buffer;
  readonly authorized: boolean;
  /**
   * Код OpenSSL из socket.authorizationError (CERT_HAS_EXPIRED, UNABLE_TO_GET_ISSUER_CERT…) при authorized: false — только
   * вида TLS_ERROR_CODE (КТ1 К3.2 № 9): TLS_NOT_AUTHORIZED стоит раньше своих шагов и скрывает причину — она в журнал рядом.
   */
  readonly authorizationError?: string;
}

/** Код OpenSSL — заглавные буквы, цифры, «_»; иное (текст, объект) в журнал не пишется. */
export const TLS_ERROR_CODE = /^[A-Z0-9_]{1,64}$/;

export type ChannelResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reject: ChannelReject; readonly tlsError?: string }
  | { readonly ok: false; readonly cause: unknown };

/** SAN сертификата агента — ровно один URI urn:<код агента песочницы> (РП65 п. 2, нюанс 3); иначе undefined. */
function agentCodeOf(cert: X509Certificate): string | undefined {
  const m = /^URI:urn:([^\s,"]+)$/.exec(cert.subjectAltName ?? "");
  const code = m?.[1];
  return code !== undefined && isSandboxAgentCode(code) ? code : undefined;
}

/**
 * Шаги РП66 п. 1: сертификат есть → TLS подтвердил цепочку (authorized) → выпущен УЦ песочницы → SAN — ровно один URI
 * агента → запись реестра того же агента и с теми же байтами → код из SAN = x-agent-code → срок по часам Платформы и
 * отзыв. authorized — условие в дополнение к своей проверке, а не вместо неё: TLS смотрит системные часы, своя проверка —
 * часы Платформы и реестр. xAgentCode — значение заголовка как пришло: повтор (массив) или нет — несовпадение.
 */
export async function checkChannel(
  client: ClientCertificate | undefined,
  xAgentCode: string | readonly string[] | undefined,
  now: Date,
  opts: ChannelOptions,
): Promise<ChannelResult> {
  if (client === undefined || client.der.length === 0) return { ok: false, reject: "NO_CERTIFICATE" };
  if (client.authorized !== true) {
    const e = client.authorizationError;
    return { ok: false, reject: "TLS_NOT_AUTHORIZED", ...(e !== undefined && TLS_ERROR_CODE.test(e) ? { tlsError: e } : {}) };
  }
  const der = client.der;

  let cert: X509Certificate;
  try {
    cert = new X509Certificate(der);
  } catch {
    return { ok: false, reject: "NOT_ISSUED_BY_CA" };
  }
  if (!cert.checkIssued(opts.ca) || !cert.verify(opts.ca.publicKey)) return { ok: false, reject: "NOT_ISSUED_BY_CA" };

  const code = agentCodeOf(cert);
  if (code === undefined) return { ok: false, reject: "SUBJECT_NOT_AGENT" };

  // Node отдаёт серийный номер hex в верхнем регистре, реестр хранит в нижнем (РП65 нюанс 12); ведущих нулей нет —
  // newSerial ставит старшие биты 01 (ca.ts), поэтому запись Node и serial.toString("hex") совпадают по длине.
  let record: AgentCertificateRecord | undefined;
  try {
    record = await opts.getCertificate(cert.serialNumber.toLowerCase());
  } catch (e) {
    return { ok: false, cause: e };
  }
  // Байты — те же, что выданы: запись реестра — источник истины (инвариант 5), а не серийный номер сам по себе.
  if (!record || record.agent_code !== code || record.der !== der.toString("base64")) return { ok: false, reject: "NOT_IN_REGISTRY" };

  if (typeof xAgentCode !== "string" || xAgentCode !== code) return { ok: false, reject: "CODE_MISMATCH" };

  // Неразбираемое время — отказ, а не допуск: сравнения с NaN ложны, и срок прошёл бы (инвариант 3; как в ca.ts).
  const t = now.getTime();
  const notBefore = Date.parse(record.not_before);
  const notAfter = Date.parse(record.not_after);
  if (![t, notBefore, notAfter].every(Number.isFinite)) return { ok: false, reject: "OUTSIDE_VALIDITY" };
  if (t < notBefore || t >= notAfter) return { ok: false, reject: "OUTSIDE_VALIDITY" };
  if (record.revoked_at !== null) return { ok: false, reject: "REVOKED" };
  return { ok: true };
}
