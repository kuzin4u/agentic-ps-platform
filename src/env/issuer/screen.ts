// Экран мандатов в приложении банка стенда (UI-К2; ROADMAP В1): эталонный модуль `src/ui/mandates/` с данными стенда.
// Эмулятор эмитента — банк: клиент уже опознан (на стенде — тест выдаёт ссылку входа по principal_ref), действия —
// подписью ключа stand:issuer-emulator по ПИ-8 того же сервера (как stand.issuer). Чтения — хранилища стенда в памяти
// (DECISIONS РП36 «Нюанс UI-К2 ч. 1» п. 2): список id мандатов и экран мандата журнала, запросы подтверждения П6 (ч. 2,
// «Нюанс UI-К2 ч. 2»); для настоящего банка нужны
// чтения ПИ-8 — DECISIONS РП74 (код — «перед пилотом с банком»). Мандат клиента — по principal_ref записи MANDATE_REQUESTED: на стенде один банк
// (РП36 доп. п. 8), привязка мандата к банку до подписи — с чтениями ПИ-8.
import type { MandateSigningView } from "../../consent/journal.js";
import { totalsHash, type ConfirmationRecord } from "../../confirm/model.js";
import { createMandatesScreen, type MandatesScreen } from "../../ui/mandates/index.js";
import type {
  ConfirmDecision,
  ConfirmResult,
  DecideResult,
  MandateDecision,
  MandatesScreenPort,
  ScreenAgent,
  ScreenConfirmation,
  ScreenHistoryEntry,
  ScreenMandate,
  ScreenNotification,
} from "../../ui/mandates/port.js";
import type { ScreenSessionTtl } from "../../ui/mandates/session.js";
import type { UiSettings } from "../../ui/shared/index.js";

/** Сроки входа на стенде (решение владельца 02.11: ссылка одноразовая и с коротким сроком). */
export const STAND_SCREEN_TTL: ScreenSessionTtl = { login_ttl_sec: 120, session_ttl_sec: 900 };

/** Лимит частоты экрана на стенде — обращений за 30 с с адреса (решение владельца 02.11, CodeQL #88). Банк задаёт свой. */
export const STAND_SCREEN_RATE_LIMIT_PER_30S = 600;

export interface IssuerScreenDeps {
  readonly now: () => Date;
  readonly settings?: UiSettings;
  /** id мандатов стенда по порядку записи (MemoryConsentStore.mandateIds — только стенд). */
  readonly mandateIds: () => readonly string[];
  /** Экран мандата журнала (ConsentJournal.signingView). */
  readonly signingView: (id: string) => Promise<MandateSigningView | undefined>;
  /** Решение клиента — запись, подписанная банком стенда, по ПИ-8 (stand.issuer.sign). */
  readonly sign: (id: string, opts: { readonly decision: MandateDecision; readonly token_consent: boolean }) => Promise<Reply>;
  /** Отзыв мандата клиентом по ПИ-8 (stand.issuer.revoke). */
  readonly revoke: (id: string) => Promise<Reply>;
  /** Отзыв всех полномочий клиента по ПИ-8 (stand.issuer.revokeAll). */
  readonly revokeAll: (principal_ref: string, revocation_ref: string) => Promise<Reply>;
  /** id запросов подтверждения стенда по порядку записи (MemoryConfirmationStore.confirmationIds — только стенд). */
  readonly confirmationIds: () => readonly string[];
  /** Запрос подтверждения П6 (ConfirmationStore.get). */
  readonly confirmationRecord: (id: string) => Promise<ConfirmationRecord | undefined>;
  /** Решение человека — запись, подписанная банком стенда над totals_hash из формы, по ПИ-8 (stand.issuer.confirm). */
  readonly confirm: (id: string, opts: { readonly decision: ConfirmDecision; readonly totals_hash: string }) => Promise<Reply>;
  /** Агент из реестра стенда (registry.get — только стенд, РП36 «Нюанс UI-К2 ч. 2»); нет — undefined, сбой — исключение. */
  readonly agent: (agent_code: string) => Promise<ScreenAgent | undefined>;
  /**
   * Записи журнала мандата (выписка `ConsentJournal.evidence` по агенту мандата — только стенд, РП36 «Нюанс UI-К2 ч. 3»):
   * у банка чтения истории в ПИ-8 нет. Неизвестный — undefined, сбой — исключение.
   */
  readonly journal: (id: string, agent_code: string) => Promise<StandJournal | undefined>;
  /** Страница ленты уведомлений банка стенда по ПИ-8 `GET /participants/v1/notifications` (stand.issuer.getNotifications). */
  readonly notificationsPage: (after?: string) => Promise<Reply>;
}

/** Выписка журнала мандата: цельность и записи цепочки (у CART — с записями родителя). */
export interface StandJournal {
  readonly integrity?: string;
  readonly records?: readonly { readonly kind: string; readonly ref: string; readonly at: string; readonly payload: Record<string, unknown> }[];
}

type Reply = { readonly statusCode: number; readonly body: unknown };

/** Предел страниц ленты за одно чтение экрана: дальше — сбой (503), а не бесконечный цикл. */
const NOTIFICATION_PAGES_MAX = 100;

const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);

const toHistory = (r: NonNullable<StandJournal["records"]>[number]): ScreenHistoryEntry => {
  const amount = r.payload.amount_limit;
  const currency = r.payload.currency;
  // Предел — только у записи запроса и только парой с валютой (правило совместимости 2).
  const limit = r.kind === "MANDATE_REQUESTED" && Number.isSafeInteger(amount) && typeof currency === "string" ? { amount_limit: amount as number, currency } : {};
  return { at: r.at, kind: r.kind, mandate_id: r.ref, ...limit };
};

const toScreen = (v: MandateSigningView): ScreenMandate => ({
  id: v.id,
  agent_code: v.agent_code,
  type: v.type,
  parent_id: v.parent_id,
  status: v.status,
  amount_limit: v.amount_limit,
  currency: v.currency,
  valid_to: v.valid_to,
  merchant_scope: v.merchant_scope,
  subject: v.subject,
  cart: v.cart ?? null,
  hash: v.hash,
});

const toConfirmation = (r: ConfirmationRecord): ScreenConfirmation => ({
  id: r.confirmation_id,
  agent_code: r.agent_code,
  mandate_id: r.mandate_id,
  merchant_id: r.merchant_id,
  amount: r.amount,
  currency: r.currency,
  order_ref: r.order_ref,
  status: r.status,
  expires_at: r.expires_at,
  totals_hash: totalsHash(r),
});

export function issuerScreenPort(deps: IssuerScreenDeps): MandatesScreenPort {
  const own = async (principal_ref: string, id: string): Promise<MandateSigningView | undefined> => {
    const v = await deps.signingView(id);
    return v && v.principal_ref === principal_ref ? v : undefined;
  };
  // Запрос клиента — по principal_ref мандата запроса (решение владельца 03.11); мандат не найден — как чужой (fail-closed).
  const ownConfirmation = async (principal_ref: string, id: string): Promise<ConfirmationRecord | undefined> => {
    const r = await deps.confirmationRecord(id);
    return r && (await own(principal_ref, r.mandate_id)) ? r : undefined;
  };
  return {
    agent: (agent_code) => deps.agent(agent_code),
    async history(principal_ref, id) {
      const v = await own(principal_ref, id);
      if (!v) return undefined;
      const j = await deps.journal(id, v.agent_code);
      // Нарушенная цепочка — не история, а сбой (инвариант 3): экран отвечает 503, записи не показываются.
      if (!j || j.integrity !== "OK" || !j.records) throw new Error("экран мандатов: журнал мандата не прочитан или цепочка нарушена");
      return j.records.map(toHistory);
    },
    async notifications(principal_ref) {
      // Лента банка — ПИ-8 с подписью запроса банка (как у настоящего банка); клиент — по principal_ref уведомления.
      const out: ScreenNotification[] = [];
      let after: string | undefined;
      for (let i = 0; i < NOTIFICATION_PAGES_MAX; i++) {
        const res = await deps.notificationsPage(after);
        const list = (res.body as { notifications?: unknown } | null)?.notifications;
        if (res.statusCode !== 200 || !Array.isArray(list)) throw new Error(`экран мандатов: ПИ-8 notifications ответил ${res.statusCode}`);
        if (list.length === 0) return out;
        for (const n of list as { notification_id?: unknown; type?: unknown; at?: unknown; data?: Record<string, unknown> }[]) {
          const d = n.data ?? {};
          if (d.principal_ref !== principal_ref) continue;
          const type = str(n.type);
          const at = str(n.at);
          if (!type || !at) throw new Error("экран мандатов: уведомление не по форме");
          const mandate_id = str(d.mandate_id);
          const agent_code = str(d.agent_code);
          const reason = str(d.reason);
          out.push({ at, type, ...(mandate_id ? { mandate_id } : {}), ...(agent_code ? { agent_code } : {}), ...(reason ? { reason } : {}) });
        }
        after = str((list[list.length - 1] as { notification_id?: unknown }).notification_id);
        if (!after) throw new Error("экран мандатов: уведомление без notification_id");
      }
      throw new Error("экран мандатов: лента уведомлений длиннее предела страниц");
    },
    async confirmations(principal_ref) {
      const out: ScreenConfirmation[] = [];
      for (const id of deps.confirmationIds()) {
        const r = await ownConfirmation(principal_ref, id);
        if (r) out.push(toConfirmation(r));
      }
      return out;
    },
    async confirmation(principal_ref, id) {
      const r = await ownConfirmation(principal_ref, id);
      return r && toConfirmation(r);
    },
    async confirm(principal_ref, id, decision, totals_hash): Promise<ConfirmResult> {
      if (!(await ownConfirmation(principal_ref, id))) return { kind: "NOT_FOUND" };
      // Хэш — из формы: итог, который видел человек, а не пересчитанный при нажатии (инвариант 7, РП50 п. 4).
      const res = await deps.confirm(id, { decision, totals_hash });
      const body = (res.body ?? {}) as { status?: unknown; code?: unknown };
      const status = typeof body.status === "string" ? body.status : undefined;
      if (res.statusCode === 200 && status) return { kind: "DONE", status };
      if (res.statusCode === 409 && body.code === "CONFIRMATION_TOTALS_MISMATCH") return { kind: "TOTALS_CHANGED" };
      if (res.statusCode === 409 && body.code === "CONFIRMATION_NOT_PENDING") return status ? { kind: "NOT_PENDING", status } : { kind: "NOT_PENDING" };
      if (res.statusCode === 404) return { kind: "NOT_FOUND" };
      // Прочее (401 подписи банка, 503 Платформы, неожиданный ответ) — сбой: экран отвечает 503 (fail-closed).
      throw new Error(`экран мандатов: ПИ-8 confirmations ответил ${res.statusCode}`);
    },
    async mandates(principal_ref) {
      const out: ScreenMandate[] = [];
      for (const id of deps.mandateIds()) {
        const v = await own(principal_ref, id);
        if (v) out.push(toScreen(v));
      }
      return out;
    },
    async mandate(principal_ref, id) {
      const v = await own(principal_ref, id);
      return v && toScreen(v);
    },
    async decide(principal_ref, id, decision): Promise<DecideResult> {
      if (!(await own(principal_ref, id))) return { kind: "NOT_FOUND" };
      // Подпись и согласие на токен — одно действие (РП12); отказ — без согласия (правка по /audit К1.2).
      const res = await deps.sign(id, { decision, token_consent: decision === "SIGN" });
      const body = (res.body ?? {}) as { status?: unknown; code?: unknown };
      const status = typeof body.status === "string" ? body.status : undefined;
      if (res.statusCode === 200 && status) return { kind: "DONE", status };
      if (res.statusCode === 422 && body.code === "QUALIFIED_SIGNATURE_REQUIRED") return { kind: "QUALIFIED_SIGNATURE_REQUIRED" };
      if (res.statusCode === 409 && body.code === "MANDATE_NOT_PENDING") {
        // Тело 409 ПИ-8 — только код: текущий статус человеку — из записи (инвариант 5).
        const now = status ?? (await own(principal_ref, id))?.status;
        return now ? { kind: "NOT_PENDING", status: now } : { kind: "NOT_PENDING" };
      }
      if (res.statusCode === 404) return { kind: "NOT_FOUND" };
      // Прочее (401 подписи банка, 503 Платформы, неожиданный ответ) — сбой: экран отвечает 503 (fail-closed).
      throw new Error(`экран мандатов: ПИ-8 sign ответил ${res.statusCode}`);
    },
    async revoke(principal_ref, id) {
      if (!(await own(principal_ref, id))) return { kind: "NOT_FOUND" };
      const res = await deps.revoke(id);
      const status = (res.body as { status?: unknown } | null)?.status;
      if (res.statusCode === 200 && typeof status === "string") return { kind: "DONE", status };
      if (res.statusCode === 404) return { kind: "NOT_FOUND" };
      throw new Error(`экран мандатов: ПИ-8 revoke ответил ${res.statusCode}`);
    },
    async revokeAll(principal_ref, revocation_ref) {
      const res = await deps.revokeAll(principal_ref, revocation_ref);
      const revoked = (res.body as { revoked?: unknown } | null)?.revoked;
      if (res.statusCode === 200 && Number.isSafeInteger(revoked) && (revoked as number) >= 0) return { revoked: revoked as number };
      // 503 — повтор тем же revocation_ref (ПИ-8); прочее — сбой.
      throw new Error(`экран мандатов: ПИ-8 revoke-all ответил ${res.statusCode}`);
    },
  };
}

export function createIssuerScreen(deps: IssuerScreenDeps): MandatesScreen {
  return createMandatesScreen({
    port: issuerScreenPort(deps),
    ttl: STAND_SCREEN_TTL,
    rate_limit_per_30s: STAND_SCREEN_RATE_LIMIT_PER_30S,
    now: deps.now,
    ...(deps.settings ? { settings: deps.settings } : {}),
  });
}
