// Экран мандатов в приложении банка стенда (UI-К2; ROADMAP В1): эталонный модуль `src/ui/mandates/` с данными стенда.
// Эмулятор эмитента — банк: клиент уже опознан (на стенде — тест выдаёт ссылку входа по principal_ref), действия —
// подписью ключа stand:issuer-emulator по ПИ-8 того же сервера (как stand.issuer). Чтения — хранилища стенда в памяти
// (DECISIONS РП36 «Нюанс UI-К2 ч. 1» п. 2): список id мандатов и экран мандата журнала; для настоящего банка нужны
// чтения ПИ-8 — STATUS «Открыто». Мандат клиента — по principal_ref записи MANDATE_REQUESTED: на стенде один банк
// (РП36 доп. п. 8), привязка мандата к банку до подписи — с чтениями ПИ-8.
import type { MandateSigningView } from "../../consent/journal.js";
import { createMandatesScreen, type MandatesScreen } from "../../ui/mandates/index.js";
import type { DecideResult, MandateDecision, MandatesScreenPort, ScreenMandate } from "../../ui/mandates/port.js";
import type { ScreenSessionTtl } from "../../ui/mandates/session.js";
import type { UiSettings } from "../../ui/shared/index.js";

/** Сроки входа на стенде (решение владельца 02.11: ссылка одноразовая и с коротким сроком). */
export const STAND_SCREEN_TTL: ScreenSessionTtl = { login_ttl_sec: 120, session_ttl_sec: 900 };

export interface IssuerScreenDeps {
  readonly now: () => Date;
  readonly settings?: UiSettings;
  /** id мандатов стенда по порядку записи (MemoryConsentStore.mandateIds — только стенд). */
  readonly mandateIds: () => readonly string[];
  /** Экран мандата журнала (ConsentJournal.signingView). */
  readonly signingView: (id: string) => Promise<MandateSigningView | undefined>;
  /** Решение клиента — запись, подписанная банком стенда, по ПИ-8 (stand.issuer.sign). */
  readonly sign: (id: string, decision: MandateDecision) => Promise<{ readonly statusCode: number; readonly body: unknown }>;
}

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

export function issuerScreenPort(deps: IssuerScreenDeps): MandatesScreenPort {
  const own = async (principal_ref: string, id: string): Promise<MandateSigningView | undefined> => {
    const v = await deps.signingView(id);
    return v && v.principal_ref === principal_ref ? v : undefined;
  };
  return {
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
      const res = await deps.sign(id, decision);
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
  };
}

export function createIssuerScreen(deps: IssuerScreenDeps): MandatesScreen {
  return createMandatesScreen({
    port: issuerScreenPort(deps),
    ttl: STAND_SCREEN_TTL,
    now: deps.now,
    ...(deps.settings ? { settings: deps.settings } : {}),
  });
}
