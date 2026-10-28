// П1 Реестр агентов: допуск по заявлению с первым ключом, класс, уровень, статус (SPEC §3, ФП1, A2, РП17, РП21, РП23).
// Класс и уровень агента — только отсюда, не из тела запросов агента (инвариант 5).
import type { SandboxCa } from "./ca/ca.js";
import { parseCsr, type CsrRejection } from "./ca/csr.js";
import { REGISTRY_ISSUER, parseAgentCode, type AgentCode } from "./code.js";
import {
  ADMISSION_LEVEL,
  AGENT_CLASSES,
  isOneOf,
  type AdmissionRefusal,
  type AgentCertificateRecord,
  type AgentRecord,
  type AgentSubscription,
  type Contour,
} from "./model.js";
import { DEFAULT_KEY_ALGORITHMS, newAgentKey, parseKey, type AgentKey, type KeyAlgorithm, type KeyPolicy } from "./keys.js";
import { checkTransition } from "./status.js";
import { AgentCodeTakenError, KeyTakenError, type AgentRegistryStore } from "./store.js";

export type AdmissionDecision =
  | {
      readonly admitted: true;
      readonly record: AgentRecord;
      readonly key: AgentKey;
      /** Сертификат mTLS — только если выдан по CSR заявления (РП65 п. 1, 3). */
      readonly certificate?: AgentCertificateRecord;
    }
  | { readonly admitted: false; readonly reasons: readonly [AdmissionRefusal, ...AdmissionRefusal[]] };

/** Выпуск сертификата mTLS при допуске в контуре sandbox (РП27 п. 2, РП65 п. 1). */
export interface RegistryCertificates {
  readonly ca: SandboxCa;
  /** agent_cert_ttl_days (РП65 п. 5). */
  readonly ttlDays: number;
  /** cert_not_before_backdate_sec (РП66 п. 5). */
  readonly backdateSec: number;
  /** Песочница с mTLS — CSR обязателен (нет — APPLICATION_INCOMPLETE); стенд dev — нет (РП65 п. 1). */
  readonly required: boolean;
  /** Вид причины отказа CSR — для журнала процесса; оператору — только KEY_INVALID (РП65 п. 1, РП31 п. 2). */
  readonly onRejected?: (reason: CsrRejection) => void;
}

/** Контекст вызова допуска: контур (РП17) и оператор агента — аутентифицированный вызывающий, не тело заявления. */
export interface AdmissionContext {
  readonly contour: Contour;
  readonly operator: string;
}

export class AgentNotFoundError extends Error {
  constructor(readonly agent_code: string) {
    super(`Агента нет в реестре: ${agent_code}`);
    this.name = "AgentNotFoundError";
  }
}

export class ConcurrentChangeError extends Error {
  constructor(readonly agent_code: string) {
    super(`Статус агента изменён конкурентно: ${agent_code}`);
    this.name = "ConcurrentChangeError";
  }
}

// Сведения о принципале в значениях (A2 п. 1.2, РП21 п. 2): телефон, e-mail, 13–19 цифр подряд (в том числе через пробел).
const PRINCIPAL_VALUE = [
  /(?:\+\d{1,3}|(?<![\d.])8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\d)/,
  /[^\s@]+@[^\s@]+\.[^\s@]+/,
  /(?<!\d)(?:\d ?){12,18}\d(?!\d)/,
];
const hasPrincipalValue = (v: string): boolean => PRINCIPAL_VALUE.some((re) => re.test(v));

// Слова имён полей принципала в x-system Agent Card; тип принципала — код, не сведения о нём (ПАО §8).
const PRINCIPAL_WORDS = new Set([
  "principal",
  "client",
  "customer",
  "holder",
  "payer",
  "phone",
  "email",
  "passport",
  "inn",
  "snils",
  "birth",
  "address",
  "name",
]);
const PRINCIPAL_TYPE_KEYS = new Set(["principal", "principal_type"]);
const PRINCIPAL_TYPE = /^[A-Z_]{1,32}$/;

const words = (name: string): string[] =>
  name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);

/** Значения и имена полей x-system: сведения о принципале — PRINCIPAL_DATA. */
function xSystemHasPrincipalData(node: unknown, top = true): boolean {
  if (typeof node === "string") return hasPrincipalValue(node);
  if (Array.isArray(node)) return node.some((v) => xSystemHasPrincipalData(v, false));
  if (!node || typeof node !== "object") return false;
  return Object.entries(node).some(([k, v]) => {
    if (top && PRINCIPAL_TYPE_KEYS.has(k)) return !(typeof v === "string" && PRINCIPAL_TYPE.test(v));
    if (words(k).some((w) => PRINCIPAL_WORDS.has(w))) return true;
    return xSystemHasPrincipalData(v, false);
  });
}

const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const text = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v : null);

export interface RegistryOptions {
  /** Сроки ключей (PARAMS.md, РП23 п. 4). */
  readonly keys: KeyPolicy;
  readonly now?: () => Date;
  /** Алгоритмы ключей по контуру — точка расширения РП5; по умолчанию DEFAULT_KEY_ALGORITHMS. */
  readonly algorithms?: Readonly<Record<Contour, readonly KeyAlgorithm[]>>;
  /** УЦ песочницы; без него поле csr не читается и сертификат не выдаётся (рабочий сервер до SEC-1-кода ч. 2, РП65 п. 1). */
  readonly certificates?: RegistryCertificates;
}

export class AgentRegistry {
  private readonly now: () => Date;
  private readonly policy: KeyPolicy;
  private readonly algorithms: Readonly<Record<Contour, readonly KeyAlgorithm[]>>;
  private readonly certificates: RegistryCertificates | undefined;

  constructor(
    private readonly store: AgentRegistryStore,
    opts: RegistryOptions,
  ) {
    this.policy = opts.keys;
    this.now = opts.now ?? (() => new Date());
    this.algorithms = opts.algorithms ?? DEFAULT_KEY_ALGORITHMS;
    this.certificates = opts.certificates;
  }

  /**
   * Решение по заявлению оператора агента. Отказ — только по закрытому перечню РП21 п. 2, все применимые основания сразу;
   * заявление без оснований отказа допускается на одинаковых условиях для всех операторов (A6 п. 2.1).
   */
  async admit(application: unknown, ctx: AdmissionContext): Promise<AdmissionDecision> {
    const { contour } = ctx;
    if (contour !== "sandbox" && contour !== "operator") throw new Error(`Неизвестный контур: ${String(contour)}`);
    // Оператор — из контекста вызова, не из заявления (РП21 п. 2; до аутентификации — расхождение №9).
    const operator = text(ctx.operator);
    if (!operator) throw new Error("Нет оператора агента в контексте вызова");
    const a = (
      typeof application === "object" && application !== null && !Array.isArray(application) ? application : {}
    ) as Record<string, unknown>;
    const reasons = new Set<AdmissionRefusal>();

    // Учитываются только поля белого списка РП21 п. 2; прочие не читаются и в запись не попадают.
    const model = text(own(a, "model"));
    const runtime = text(own(a, "runtime"));
    const rawCode = own(a, "agent_code");
    const alg = own(a, "alg");
    const publicKey = own(a, "public_key");
    if (!model || !runtime || rawCode === undefined || alg === undefined || publicKey === undefined) {
      reasons.add("APPLICATION_INCOMPLETE");
    }

    // Код — грамматика РП21 п. 1 и выдавшая сторона только nspk:agent (РП23 п. 1).
    let code: AgentCode | null = null;
    if (rawCode !== undefined) {
      try {
        code = parseAgentCode(rawCode);
      } catch {
        reasons.add("CODE_INVALID");
      }
      if (code && code.issuer !== REGISTRY_ISSUER) {
        code = null;
        reasons.add("CODE_INVALID");
      }
    }

    // Первый ключ (РП23 п. 2–3): alg из перечня контура, разбираемый ключ, kid ещё не зарегистрирован.
    const parsedKey = parseKey(this.algorithms[contour], alg, publicKey);
    if (alg !== undefined && publicKey !== undefined && (!parsedKey || (await this.store.getKey(parsedKey.kid)))) {
      reasons.add("KEY_INVALID");
    }

    // CSR сертификата mTLS (РП65 п. 1): только в sandbox и только при УЦ; в контуре operator — УЦ оператора (РП27 п. 6).
    const certs = contour === "sandbox" ? this.certificates : undefined;
    const csr = certs ? own(a, "csr") : undefined;
    if (certs?.required && csr === undefined) reasons.add("APPLICATION_INCOMPLETE");
    if (certs && csr !== undefined) {
      const parsed = parseCsr(csr);
      if (!parsed.ok) {
        reasons.add("KEY_INVALID");
        certs.onRejected?.(parsed.reason);
      }
    }

    const cls = own(a, "class");
    if (!isOneOf(AGENT_CLASSES, cls)) reasons.add("CLASS_UNKNOWN");

    if ((model && hasPrincipalValue(model)) || (runtime && hasPrincipalValue(runtime))) reasons.add("PRINCIPAL_DATA");

    const card = own(a, "agent_card");
    if (card !== undefined) {
      const ext = card && typeof card === "object" ? own(card as Record<string, unknown>, "x-system") : undefined;
      const x = (ext && typeof ext === "object" && !Array.isArray(ext) ? ext : {}) as Record<string, unknown>;
      if (own(x, "agent_code") !== rawCode || own(x, "class") !== cls) reasons.add("AGENT_CARD_MISMATCH");
      if (xSystemHasPrincipalData(x)) reasons.add("PRINCIPAL_DATA");
    }

    // В песочнице допуск — для прохождения набора, ссылка не нужна и не записывается (РП17).
    const conformance = contour === "operator" ? text(own(a, "conformance_run_ref")) : null;
    if (contour === "operator" && !conformance) reasons.add("CONFORMANCE_MISSING");

    // Код занят: выдан ровно этот код, или «сторона : идентификатор» принадлежит другому оператору (A2 п. 4.1).
    const owner = code ? await this.store.ownerOf(code.issuer, code.id) : undefined;
    if (code && ((await this.store.get(code.code)) || (owner !== undefined && owner !== operator))) reasons.add("CODE_TAKEN");

    const [first, ...rest] = [...reasons];
    if (first) return { admitted: false, reasons: [first, ...rest] };
    if (!code || !model || !runtime || !isOneOf(AGENT_CLASSES, cls) || !parsedKey) {
      throw new Error("Заявление без оснований отказа неполно — нарушен закрытый перечень РП21");
    }

    const now = this.now();
    const at = now.toISOString();
    const record: AgentRecord = {
      agent_code: code.code,
      issuer: code.issuer,
      id: code.id,
      version: code.version,
      operator,
      class: cls,
      level: ADMISSION_LEVEL,
      status: "ACTIVE",
      status_ground: null,
      model,
      runtime,
      contour,
      conformance_run_ref: conformance,
      admitted_at: at,
      status_changed_at: at,
      suspended_at: null,
      row_version: 1,
    };
    // Сертификат — по коду из записи, не из CSR (инвариант 5); CSR уже разобран выше, отказ здесь — нарушение порядка.
    let certificate: AgentCertificateRecord | undefined;
    if (certs && csr !== undefined) {
      const issued = certs.ca.issueAgentCertificate(csr, record.agent_code, now, certs.ttlDays, certs.backdateSec);
      if (!issued.ok) throw new Error(`CSR прошёл разбор, но не выпуск: ${issued.reason}`);
      certificate = { ...issued.certificate, agent_code: record.agent_code, revoked_at: null };
    }
    try {
      await this.store.insert(record, newAgentKey(record.agent_code, parsedKey, now, this.policy), certificate);
    } catch (e) {
      if (e instanceof AgentCodeTakenError) return { admitted: false, reasons: ["CODE_TAKEN"] };
      if (e instanceof KeyTakenError) return { admitted: false, reasons: ["KEY_INVALID"] };
      throw e;
    }
    const decision = {
      admitted: true,
      record: (await this.store.get(record.agent_code)) as AgentRecord,
      key: (await this.store.getKey(parsedKey.kid)) as AgentKey,
    } as const;
    return certificate ? { ...decision, certificate: (await this.store.getCertificate(certificate.serial)) as AgentCertificateRecord } : decision;
  }

  /** Сертификат mTLS по серийному номеру — из хранилища на каждом вызове (РП65 п. 3). */
  getCertificate(serial: string): Promise<AgentCertificateRecord | undefined> {
    return this.store.getCertificate(serial);
  }

  certificatesOf(agent_code: string): Promise<readonly AgentCertificateRecord[]> {
    return this.store.certificatesOf(agent_code);
  }

  /**
   * Отзыв сертификата mTLS (РП27 п. 4, РП65 п. 3): при компрометации ключа сертификата и по заявлению оператора; необратим,
   * повтор — тот же отозванный с прежним revoked_at; нет такого — undefined. По HTTP — PS-31; проверка списка — ч. 2.
   */
  revokeCertificate(serial: string): Promise<AgentCertificateRecord | undefined> {
    return this.store.revokeCertificate(serial, this.now().toISOString());
  }

  /** Запись агента — из хранилища на каждом вызове (РП64 п. 3); сбой чтения — отклонённое обещание. */
  get(agent_code: string): Promise<AgentRecord | undefined> {
    return this.store.get(agent_code);
  }

  /** Подписка агента на события (РП40 п. 1). */
  subscription(agent_code: string): Promise<AgentSubscription | undefined> {
    return this.store.subscriptionOf(agent_code);
  }

  /** Замена подписки: адрес уже проверен шлюзом (РП40 п. 2). Нет агента — исключение. */
  async subscribe(agent_code: string, subscription: AgentSubscription): Promise<AgentSubscription> {
    if (!(await this.store.setSubscription(agent_code, subscription))) throw new AgentNotFoundError(agent_code);
    return (await this.store.subscriptionOf(agent_code)) as AgentSubscription;
  }

  /** Переход статуса по РП21 п. 4. Нет агента, недопустимый переход или конкурентное изменение — исключение. */
  async changeStatus(agent_code: string, change: unknown): Promise<AgentRecord> {
    const cur = await this.store.get(agent_code);
    if (!cur) throw new AgentNotFoundError(agent_code);
    const c = checkTransition(cur.status, change);
    const at = this.now().toISOString();
    const next = await this.store.updateStatus(agent_code, cur.row_version, {
      status: c.to,
      status_ground: c.to === "ACTIVE" ? null : c.ground,
      status_changed_at: at,
      // Отсечка РП54 п. 5–6: время последнего приостановления переживает снятие и исключение.
      suspended_at: c.to === "SUSPENDED" ? at : cur.suspended_at,
    });
    if (!next) throw new ConcurrentChangeError(agent_code);
    return next;
  }
}
