// Отзыв мандата закрывает ожидающие запросы подтверждения (РП76 п. 1–3, 6): после записи отзыва (ПИ-8 revoke,
// revoke-all, ПАО relinquish) и при их повторе — каждый PENDING-запрос агента до срока, чей мандат по свёртке журнала
// REVOKED, переводится в REJECTED с closed MANDATE_REVOKED. Для INTENT это и запросы его CART: CART отозван свёрткой
// родителя (РП35), индекса дочерних нет. Сбой чтения или записи — исключение: вызывающий отвечает 503, повтор доотклоняет.
import type { ConfirmationRecord } from "./model.js";
import type { ConfirmationStore } from "./store.js";

/** Отзыв записан, а запросы подтверждения не закрыты (сбой П6 или журнала) — 503 STATE_UNAVAILABLE, повтор доотклоняет. */
export class ConfirmationsNotClosed extends Error {
  constructor(
    readonly agent_code: string,
    readonly cause: unknown,
  ) {
    super("запросы подтверждения после отзыва мандата не закрыты");
    this.name = "ConfirmationsNotClosed";
  }
}

/** Проход для одного агента; сбой — ConfirmationsNotClosed (причина — в cause). */
export type CloseRevoked = (agent_code: string) => Promise<readonly string[]>;

/**
 * Запасная проверка при старте маршрутов ПИ-8 и ПАО (Р-1374): П6 передано — передан и проход; иначе исключение.
 * Основная — тип: closeRevoked — обязательное поле рядом с хранилищем П6.
 */
export function assertCloseRevoked(confirmations: { readonly closeRevoked?: unknown } | undefined, where: string): void {
  if (confirmations && typeof confirmations.closeRevoked !== "function") {
    throw new Error(`${where}: хранилище П6 без прохода закрытия после отзыва (РП76) — сборка не стартует`);
  }
}

/** Проход п. 1 с зависимостями, для маршрутов ПИ-8 и ПАО. */
export const closeRevokedFor =
  (deps: RevokedSweepDeps): CloseRevoked =>
  async (agent_code) => {
    try {
      return await closeRevokedPending(deps, agent_code);
    } catch (err) {
      throw new ConfirmationsNotClosed(agent_code, err);
    }
  };

export interface RevokedSweepDeps {
  readonly store: Pick<ConfirmationStore, "pendingByAgent" | "closeRevoked">;
  /** Статус мандата агента по свёртке журнала (у CART — с родителем); нет — undefined. Тем же чтением, что ADP. */
  readonly mandateStatus: (mandate_id: string, agent_code: string) => Promise<string | undefined>;
  readonly now: () => Date;
}

/** Закрытые этим вызовом запросы (id по порядку записи). Закрыл другой экземпляр или срок вышел — запроса в списке нет. */
export async function closeRevokedPending(deps: RevokedSweepDeps, agent_code: string): Promise<readonly string[]> {
  const at = deps.now().toISOString();
  const pending = await deps.store.pendingByAgent(agent_code, at);
  const statuses = new Map<string, string | undefined>();
  const closed: string[] = [];
  for (const r of pending) {
    if (!statuses.has(r.mandate_id)) statuses.set(r.mandate_id, await deps.mandateStatus(r.mandate_id, agent_code));
    if (statuses.get(r.mandate_id) !== "REVOKED") continue;
    const done: ConfirmationRecord | undefined = await deps.store.closeRevoked(r.confirmation_id, at);
    if (done) closed.push(done.confirmation_id);
  }
  return closed;
}
