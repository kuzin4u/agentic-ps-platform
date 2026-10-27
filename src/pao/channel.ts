// П9 Ступень 0 проверки обращения ПАО — сертификат канала mTLS (РП27 п. 3, РП66 п. 1–2): своя проверка DER из соединения
// по часам Платформы, а не флаг TLS authorized (тот смотрит системные часы). Любой отказ — AGENT_UNKNOWN: сертификат
// канала перевыпускает оператор агента, а AGENT_KEY_REVOKED (new_key) вёл бы агента к ротации ключа подписи (РП66 п. 2).
// Вид причины — только в журнал процесса (РП31 п. 2). Сбой чтения реестра — UPSTREAM_UNAVAILABLE (РП23 доп. 4).
import { X509Certificate } from "node:crypto";
import { isSandboxAgentCode } from "../registry/ca/ca.js";
import type { AgentCertificateRecord } from "../registry/model.js";

/** Вид причины отказа ступени 0 — шаги РП66 п. 1 по порядку. */
export type ChannelReject =
  | "NO_CERTIFICATE"
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
}

export type ChannelResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reject: ChannelReject }
  | { readonly ok: false; readonly cause: unknown };

/** SAN сертификата агента — ровно один URI urn:<код агента песочницы> (РП65 п. 2, нюанс 3); иначе undefined. */
function agentCodeOf(cert: X509Certificate): string | undefined {
  const m = /^URI:urn:([^\s,"]+)$/.exec(cert.subjectAltName ?? "");
  const code = m?.[1];
  return code !== undefined && isSandboxAgentCode(code) ? code : undefined;
}

/**
 * Шаги РП66 п. 1: сертификат есть → выпущен УЦ песочницы → SAN — ровно один URI агента → запись реестра того же агента и
 * с теми же байтами → код из SAN = x-agent-code → срок по часам Платформы и отзыв. xAgentCode — значение заголовка как
 * пришло: повтор (массив) или нет — несовпадение.
 */
export async function checkChannel(
  der: Buffer | undefined,
  xAgentCode: string | readonly string[] | undefined,
  now: Date,
  opts: ChannelOptions,
): Promise<ChannelResult> {
  if (der === undefined || der.length === 0) return { ok: false, reject: "NO_CERTIFICATE" };

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
