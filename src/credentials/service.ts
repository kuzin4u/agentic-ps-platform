// П5 Выдача агентского реквизита (РП47 п. 1–5, ПАО §4): токен на CART, одноразовая криптограмма на заказ.
// Условия — из записей журнала (инвариант 5); остаток бюджета не резервируется — деньги проверяет ADP (РП11).
import type { Credential, CredentialRequest, Mandate } from "../shared/pao.js";
import type { PaoErrorCode } from "../shared/pao-errors.generated.js";
import type { Params } from "../shared/config.js";
import type { ClientRef } from "../participants/limits.js";
import {
  MCC,
  opaqueRef,
  sha256Hex,
  type CredentialRecord,
  type FundingSource,
  type MerchantDirectory,
  type MerchantMcc,
  type TokenRecord,
  type TokenServicePort,
} from "./model.js";
import type { CredentialStore } from "./store.js";

/** Мандат для выдачи: статус по свёртке (у CART — с родителем), клиент и согласие на токен корня (РП36 доп. п. 10). */
export interface CredentialMandate {
  readonly mandate: Mandate;
  readonly client: ClientRef | null;
  /** token_consent записи MANDATE_SIGNED корня; подписи корня нет — null. */
  readonly token_consent: boolean | null;
}

/** Журнал согласий: чужой или неизвестный — undefined; нарушенная цепочка и неопределённое состояние — исключение журнала. */
export interface CredentialMandates {
  get(mandate_id: string, agent_code: string): Promise<CredentialMandate | undefined>;
}

export interface CredentialsOptions {
  readonly mandates: CredentialMandates;
  readonly store: CredentialStore;
  readonly tsp: TokenServicePort;
  readonly funding: FundingSource;
  /** Справочник продавцов (РП49 (д)) — обязателен: забытый порт — ошибка сборки, а не «токен без MCC». */
  readonly merchants: MerchantDirectory;
  readonly params: Pick<Params, "cryptogram_ttl_sec">;
  readonly now?: () => Date;
  readonly log?: (fields: Record<string, unknown>, msg: string) => void;
}

export type IssueResult =
  | { readonly ok: true; readonly credential: Credential }
  | { readonly ok: false; readonly code: PaoErrorCode; readonly norm?: string; readonly message?: string };

type Refusal = Extract<IssueResult, { readonly ok: false }>;

const refuse = (code: PaoErrorCode, norm?: string, message?: string): Refusal => ({
  ok: false,
  code,
  ...(norm !== undefined ? { norm } : {}),
  ...(message !== undefined ? { message } : {}),
});

/** Статус мандата → отказ выдачи (РП47 п. 4); ACTIVE — null; статус вне перечня — не подтверждено (инвариант 3). */
function statusRefusal(status: Mandate["status"]): IssueResult | null {
  switch (status) {
    case "ACTIVE":
      return null;
    case "PENDING_SIGNATURE":
      return refuse("PRINCIPAL_SIGNATURE_PENDING", "A7 п. 3");
    case "EXPIRED":
      return refuse("MANDATE_EXPIRED", "A7 п. 2");
    case "REVOKED":
    case "REJECTED":
      return refuse("MANDATE_REVOKED", "A7 п. 6");
    case "EXHAUSTED":
      return refuse("LIMIT_EXCEEDED", "A3 п. 4");
    default:
      return refuse("STATE_UNAVAILABLE", "A3 п. 4.5");
  }
}

/**
 * Предел одного внешнего вызова П5 (РП48 (в) п. 4): выдача под ключом идемпотентности делает до четырёх вызовов (банк —
 * funding_ref, токен-сервис — токен и криптограмма; четвёртый — пересчёт при одновременной выдаче того же заказа на другом
 * экземпляре), 4 × предел меньше предела обработчика ПАО (PAO_HANDLER_BUDGET_MS) и аренды ключа.
 * Константа кода, как аренда: граница отказа, а не настройка поведения. Сам вызов не отменяется — ответ после предела
 * отбрасывается; повтор выдачи безопасен (уникальность заказа и токен на CART, РП47 п. 5, 10).
 */
export const P5_UPSTREAM_TIMEOUT_MS = 5_000;

/** Сбой хранилища П5 — не подтверждено; токен-сервиса или банка — внешний компонент недоступен. */
class Unavailable extends Error {
  constructor(readonly code: "STATE_UNAVAILABLE" | "UPSTREAM_UNAVAILABLE", cause: unknown) {
    super(code, { cause });
  }
}

export class Credentials {
  private readonly now: () => Date;
  private readonly log: (fields: Record<string, unknown>, msg: string) => void;

  constructor(private readonly opts: CredentialsOptions) {
    this.now = opts.now ?? (() => new Date());
    this.log = opts.log ?? (() => {});
  }

  /**
   * POST /pao/v1/credentials (РП47 п. 4–5). agent_code — из проверенного обращения. Повтор по заказу — тот же реквизит
   * с той же криптограммой (пересчёт с valid_to записи); тот же order_ref с другими значениями — IDEMPOTENCY_CONFLICT.
   * Исключения журнала (цепочка, состояние) — вызывающему: код по consentErrorReply. beforeWrite — проверка предела
   * обработчика ПАО перед каждой записью (РП33 доп. п. 8).
   */
  async issue(agent_code: string, req: CredentialRequest, beforeWrite: () => void = () => {}): Promise<IssueResult> {
    const read = await this.opts.mandates.get(req.mandate_id, agent_code);
    if (!read) return refuse("MANDATE_NOT_FOUND", "A7 п. 9.1");
    const m = read.mandate;
    const byStatus = statusRefusal(m.status);
    if (byStatus) return byStatus;
    if (m.type !== "CART") return refuse("MANDATE_SCOPE", "A7 п. 1.2");
    // Согласие на токен — в подписи корня (РП12, РП36 доп. п. 10): без него токен не выпускается; нужен новый мандат.
    if (read.token_consent !== true) return refuse("MANDATE_SCOPE", "A3 п. 2.1");
    if (!m.merchant_scope.includes(req.merchant_id) || req.currency !== m.currency || req.amount_max > m.amount_limit) {
      return refuse("MANDATE_SCOPE", "A7 п. 5");
    }
    // Вид реквизита — после мандата и области, как в РП47 п. 4 (решение владельца по ревью КТ1 З3).
    if (req.kind !== "CARD") return refuse("CREDENTIAL_INVALID", "A3 п. 2", "СБП — с PS-21; реквизит по карте — kind CARD");
    if (!read.client) return refuse("STATE_UNAVAILABLE", "A3 п. 4.5");
    try {
      return await this.issueFor(agent_code, req, m, read.client, beforeWrite);
    } catch (err) {
      if (!(err instanceof Unavailable)) throw err;
      this.log({ agent_code, mandate_id: req.mandate_id, code: err.code }, "П5: реквизит не выдан — компонент недоступен");
      return refuse(err.code);
    }
  }

  private async issueFor(
    agent_code: string,
    req: CredentialRequest,
    m: Mandate,
    client: ClientRef,
    beforeWrite: () => void,
  ): Promise<IssueResult> {
    const mandate_id = req.mandate_id;
    const prior = await this.store((s) => s.credentialByOrder(agent_code, mandate_id, req.order_ref));
    if (prior) return this.repeat(prior, req);

    const token = await this.token(agent_code, mandate_id, m, client, beforeWrite);
    if ("ok" in token) return token;
    const now = this.now();
    const ttl = now.getTime() + this.opts.params.cryptogram_ttl_sec * 1000;
    const valid_to = new Date(Math.min(ttl, Date.parse(m.valid_to))).toISOString();
    const input = {
      token_ref: token.token_ref,
      order_ref: req.order_ref,
      merchant_id: req.merchant_id,
      amount_max: req.amount_max,
      currency: req.currency,
      valid_to,
    };
    const cryptogram = await this.upstream(() => this.opts.tsp.cryptogram(input));
    const rec: CredentialRecord = {
      credential_ref: opaqueRef("crd_"),
      agent_code,
      mandate_id,
      ...input,
      cryptogram_sha256: sha256Hex(cryptogram),
      status: "ISSUED",
      op_ref: null,
      created_at: now.toISOString(),
    };
    beforeWrite();
    const stored = await this.store((s) => s.putCredential(rec));
    // Одновременная выдача того же заказа на другом экземпляре записала первой — её реквизит, как повтор.
    if (stored.credential_ref !== rec.credential_ref) return this.repeat(stored, req);
    return { ok: true, credential: this.view(stored, cryptogram) };
  }

  /** Повтор заказа: те же значения — тот же реквизит, криптограмма пересчитана с valid_to записи (РП47 п. 3, 5). */
  private async repeat(prior: CredentialRecord, req: CredentialRequest): Promise<IssueResult> {
    if (prior.merchant_id !== req.merchant_id || prior.amount_max !== req.amount_max || prior.currency !== req.currency) {
      return refuse("IDEMPOTENCY_CONFLICT");
    }
    return { ok: true, credential: this.view(prior, await this.recompute(prior)) };
  }

  /**
   * Повтор под Idempotency-Key (РП48 (в)): под ключом сохранён ответ без криптограммы, тело запроса то же (хэш тела —
   * у ядра). Реквизит — по заказу из тела, сверка с credential_ref сохранённого ответа; криптограмма пересчитана, status —
   * текущий, как у повтора по заказу. Мандат не перепроверяется: повтор под ключом — прежний ответ, а не новая выдача.
   * Записи нет или она другая — не подтверждено и инцидент (инвариант 3).
   */
  async replay(agent_code: string, req: CredentialRequest, credential_ref: string): Promise<IssueResult> {
    try {
      const prior = await this.store((s) => s.credentialByOrder(agent_code, req.mandate_id, req.order_ref));
      if (!prior || prior.credential_ref !== credential_ref) {
        this.log({ agent_code, credential_ref, incident: true }, "П5: повтор под ключом — запись реквизита не найдена");
        return refuse("STATE_UNAVAILABLE", "A3 п. 4.5");
      }
      return { ok: true, credential: this.view(prior, await this.recompute(prior)) };
    } catch (err) {
      if (!(err instanceof Unavailable)) throw err;
      this.log({ agent_code, credential_ref, code: err.code }, "П5: повтор под ключом — компонент недоступен");
      return refuse(err.code);
    }
  }

  /**
   * GET /pao/v1/credentials/{ref} (РП49 (г)): свой реквизит — тот же Credential, что при повторе (криптограмма пересчитана
   * с valid_to записи и сверена с хэшем, status текущий). Чужой и неизвестный неразличимы — CREDENTIAL_INVALID: хранилище
   * ищет по паре (credential_ref, agent_code), чужой для него — «не найдено».
   */
  async get(agent_code: string, credential_ref: string): Promise<IssueResult> {
    try {
      const rec = await this.store((s) => s.credentialByRef(credential_ref, agent_code));
      if (!rec) return refuse("CREDENTIAL_INVALID");
      return { ok: true, credential: this.view(rec, await this.recompute(rec)) };
    } catch (err) {
      if (!(err instanceof Unavailable)) throw err;
      this.log({ agent_code, credential_ref, code: err.code }, "П5: реквизит по ссылке — компонент недоступен");
      return refuse(err.code);
    }
  }

  /** Пересчёт криптограммы с valid_to записи; не совпала с хэшем записи — ключ токен-сервиса сменился (инвариант 3). */
  private async recompute(prior: CredentialRecord): Promise<string> {
    const cryptogram = await this.upstream(() =>
      this.opts.tsp.cryptogram({
        token_ref: prior.token_ref,
        order_ref: prior.order_ref,
        merchant_id: prior.merchant_id,
        amount_max: prior.amount_max,
        currency: prior.currency,
        valid_to: prior.valid_to,
      }),
    );
    // Пересчёт обязан совпасть с записью: иначе ключ токен-сервиса сменился — значение не выдаём (инвариант 3).
    if (sha256Hex(cryptogram) !== prior.cryptogram_sha256) {
      this.log({ credential_ref: prior.credential_ref, incident: true }, "П5: пересчёт криптограммы не совпал с записью");
      throw new Unavailable("UPSTREAM_UNAVAILABLE", undefined);
    }
    return cryptogram;
  }

  /**
   * Токен CART (РП47 п. 2): записанный или новый; одновременный выпуск — записанный первым. Справочник продавцов читается
   * только при выпуске и до вызовов банка и токен-сервиса (РП49 (д) п. 2): отказ не оставляет выпущенного токена.
   */
  private async token(
    agent_code: string,
    mandate_id: string,
    m: Mandate,
    client: ClientRef,
    beforeWrite: () => void,
  ): Promise<TokenRecord | Refusal> {
    const prior = await this.store((s) => s.tokenByMandate(mandate_id));
    if (prior) return prior;
    const read = await this.merchantMcc(m);
    if (!read.ok) return read;
    const { merchant_mcc } = read;
    const funding_ref = await this.upstream(() => this.opts.funding.fundingRef(client));
    const domain = { agent_code, mandate_id, merchant_scope: [...m.merchant_scope], valid_to: m.valid_to, merchant_mcc };
    const { token_ref } = await this.upstream(() => this.opts.tsp.issueToken({ funding_ref, domain }));
    beforeWrite();
    return this.store((s) => s.putToken({ ...domain, token_ref, funding_ref, created_at: this.now().toISOString() }));
  }

  /**
   * Наборы MCC продавцов области CART (РП49 (д) п. 1–2). Сначала читаются записи всех продавцов и проверяется их форма
   * (не массив или MCC не из четырёх цифр — справочник не прочитан: STATE_UNAVAILABLE и инцидент, «Нюансы РП49» п. 9),
   * затем наличие (продавца нет или набор пуст — MANDATE_SCOPE, A7 п. 5): дефект справочника оператора не прячется за
   * отказом агенту (ревью КТ1 № 3). Сбой чтения — STATE_UNAVAILABLE.
   */
  private async merchantMcc(m: Mandate): Promise<{ readonly ok: true; readonly merchant_mcc: MerchantMcc } | Refusal> {
    const read: [string, unknown][] = [];
    for (const merchant_id of m.merchant_scope) {
      try {
        read.push([merchant_id, await this.opts.merchants.mccOf(merchant_id)]);
      } catch (err) {
        throw new Unavailable("STATE_UNAVAILABLE", err);
      }
    }
    for (const [merchant_id, set] of read) {
      if (set === undefined) continue;
      if (!Array.isArray(set) || !set.every((mcc) => typeof mcc === "string" && MCC.test(mcc))) {
        this.log({ mandate_id: m.id, merchant_id, incident: true }, "П5: MCC справочника продавцов не по форме");
        throw new Unavailable("STATE_UNAVAILABLE", undefined);
      }
    }
    const out: [string, readonly string[]][] = [];
    for (const [merchant_id, set] of read) {
      if (!Array.isArray(set) || set.length === 0) return refuse("MANDATE_SCOPE", "A7 п. 5");
      out.push([merchant_id, [...(set as string[])]]);
    }
    // fromEntries — собственные свойства: merchant_id «__proto__» не меняет прототип записи.
    return { ok: true, merchant_mcc: Object.fromEntries(out) };
  }

  /** Ответ ПАО: EXPIRED — по valid_to на часах Платформы; aoi — из записи, не из запроса (инвариант 5). */
  private view(rec: CredentialRecord, cryptogram: string): Credential {
    const expired = rec.status === "ISSUED" && Date.parse(rec.valid_to) <= this.now().getTime();
    return {
      credential_ref: rec.credential_ref,
      kind: "CARD",
      payload: { token_ref: rec.token_ref, cryptogram, valid_to: rec.valid_to },
      aoi: { indicator: true, agent_code: rec.agent_code, mandate_id: rec.mandate_id },
      status: expired ? "EXPIRED" : rec.status,
    };
  }

  private async store<T>(f: (s: CredentialStore) => Promise<T>): Promise<T> {
    try {
      return await f(this.opts.store);
    } catch (err) {
      throw new Unavailable("STATE_UNAVAILABLE", err);
    }
  }

  /** Внешний вызов (банк, токен-сервис) — не дольше P5_UPSTREAM_TIMEOUT_MS; сбой и таймаут — UPSTREAM_UNAVAILABLE. */
  private async upstream<T>(f: () => Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const limit = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`П5: внешний вызов дольше ${P5_UPSTREAM_TIMEOUT_MS} мс`)), P5_UPSTREAM_TIMEOUT_MS);
      timer.unref();
    });
    try {
      return await Promise.race([f(), limit]);
    } catch (err) {
      if (err instanceof Unavailable) throw err;
      throw new Unavailable("UPSTREAM_UNAVAILABLE", err);
    } finally {
      clearTimeout(timer);
    }
  }
}
