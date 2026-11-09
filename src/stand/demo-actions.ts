// Действия кнопок реакции пульта DEMO-2 (РП75 п. 6, #112) — методы stand.demo, только демо-стенд. Отзыв и отклонение —
// через банк стенда по ПИ-8, как клиент в приложении банка: защиту и события дают настоящие проверки Платформы. Продление
// срока запроса подтверждения — extendPending хранилища П6 в памяти (Р-1347): не в интерфейсе ConfirmationStore, рабочему
// серверу недоступно (страж — tests/unit/stand-boundary.test.ts).
import type { MemoryConfirmationStore } from "../confirm/store.js";
import type { DemoActionSink, DemoActions, DemoGatewayReply } from "./demo.js";

export interface DemoActionDeps {
  /** Тип мандата по журналу согласий; неизвестный — undefined. */
  readonly mandateType: (mandate_id: string) => Promise<string | undefined>;
  /** Отзыв мандата клиентом через банк стенда (ПИ-8 revoke, РП38): закрывает и ожидающие запросы подтверждения (РП76). */
  readonly revoke: (mandate_id: string) => Promise<DemoGatewayReply>;
  readonly confirmations: Pick<MemoryConfirmationStore, "get" | "confirmationIds" | "extendPending">;
  /** confirmation_remind_extend_sec. */
  readonly remindExtendSec: number;
  readonly now: () => Date;
}

export function demoActions(deps: DemoActionDeps, sink: DemoActionSink): Omit<DemoActions, "sendToReview"> {
  // Однократность «Напомнить клиенту» — на запрос (РП75 п. 6): повтор без продления.
  const reminded = new Set<string>();
  const revokeAs = async (mandate_id: string, what: "PURCHASE_STOPPED" | "MANDATE_REVOKED"): Promise<DemoGatewayReply> => {
    const res = await deps.revoke(mandate_id);
    sink.acted(res.statusCode === 200 ? what : "ACTION_REFUSED", { mandate_id });
    return res;
  };
  return {
    async stopPurchase(cart_mandate_id) {
      const type = await deps.mandateType(cart_mandate_id);
      if (type === undefined) throw new Error(`demo: мандат ${cart_mandate_id} не найден`);
      if (type !== "CART") throw new Error(`demo: остановить покупку — только CART, у ${cart_mandate_id} ${type}`);
      // Ожидающие запросы по CART до отзыва: их закрывает сам отзыв (РП76 п. 1, 8) — своего отказа нет, событие одно.
      const at = deps.now().toISOString();
      const pending: string[] = [];
      for (const id of deps.confirmations.confirmationIds()) {
        const r = await deps.confirmations.get(id);
        if (r && r.mandate_id === cart_mandate_id && r.status === "PENDING" && r.expires_at > at) pending.push(id);
      }
      const res = await revokeAs(cart_mandate_id, "PURCHASE_STOPPED");
      if (res.statusCode !== 200) return { ...res, rejected: [] };
      // Закрытые отзывом — REJECTED с closed (РП76 п. 3): по записи CONFIRMATION_REJECTED на запрос.
      const rejected: string[] = [];
      for (const id of pending) {
        const r = await deps.confirmations.get(id);
        if (r?.status !== "REJECTED" || r.closed === undefined) continue;
        rejected.push(id);
        sink.acted("CONFIRMATION_REJECTED", { mandate_id: cart_mandate_id, confirmation_id: id });
      }
      return { ...res, rejected };
    },
    async remindClient(confirmation_id) {
      const r = await deps.confirmations.get(confirmation_id);
      if (!r) throw new Error(`demo: запрос подтверждения ${confirmation_id} не найден`);
      const at = deps.now().toISOString();
      if (r.status !== "PENDING" || !(r.expires_at > at)) throw new Error(`demo: запрос ${confirmation_id} не ожидает решения`);
      const ids = { confirmation_id, mandate_id: r.mandate_id, merchant_id: r.merchant_id, order_ref: r.order_ref };
      if (reminded.has(confirmation_id)) {
        sink.acted("REMIND_REPEATED", ids);
        return { confirmation_id, expires_at: r.expires_at, extended: false };
      }
      const next = await deps.confirmations.extendPending(confirmation_id, deps.remindExtendSec, at);
      if (!next) throw new Error(`demo: запрос ${confirmation_id} не ожидает решения`);
      reminded.add(confirmation_id);
      // Удержание заказа у витрины — на столько же (order_ref запроса = номер заказа у продавца): иначе заказ отменится
      // раньше запроса (РП75 п. 6).
      sink.extendHold(r.merchant_id, r.order_ref, deps.remindExtendSec * 1000);
      sink.acted("CLIENT_REMINDED", ids);
      return { confirmation_id, expires_at: next.expires_at, extended: true };
    },
    async revokeMandate(mandate_id) {
      if ((await deps.mandateType(mandate_id)) === undefined) throw new Error(`demo: мандат ${mandate_id} не найден`);
      return revokeAs(mandate_id, "MANDATE_REVOKED");
    },
  };
}
