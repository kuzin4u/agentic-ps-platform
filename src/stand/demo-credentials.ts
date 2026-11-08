// Н-02 демо-стенда (РП75 п. 3, #112): «платёжная система не отсекла повтор» — следующий новый запрос реквизита того же
// заказа получает второй реквизит. Подмена — только в сборке стенда с режимом сбоев: обёртка хранилища П5 и вызова выдачи;
// src/credentials не меняется. Повтор под тем же Idempotency-Key (replay) не затрагивается — флаг ставит только issue.
import type { Credentials } from "../credentials/index.js";
import type { CredentialRecord } from "../credentials/model.js";
import type { CredentialStore } from "../credentials/store.js";
import type { DemoFaults } from "./demo.js";

const orderKey = (agent_code: string, mandate_id: string, order_ref: string): string => JSON.stringify([agent_code, mandate_id, order_ref]);
const cryptogramKey = (token_ref: string, sha: string): string => JSON.stringify([token_ref, sha]);

export interface DemoCredentials {
  /** Хранилище П5 для всех читателей стенда (выдача, ADP, сверка): второй реквизит виден им, как настоящий. */
  readonly store: CredentialStore;
  /** Выдача с подменой Н-02 — вместо сервиса П5 в шлюзе ПАО. */
  wrap(credentials: Credentials): Credentials;
}

export function demoCredentials(raw: CredentialStore, faults: DemoFaults): DemoCredentials {
  /** Второй реквизит заказа — вне индекса «заказ → реквизит» хранилища: прежний остаётся реквизитом заказа. */
  const extra = new Map<string, CredentialRecord>();
  const extraByCryptogram = new Map<string, string>();
  /** Заказ, для которого идущая выдача должна дать новый реквизит; один на стенд, на время одного вызова issue. */
  let forceNew: string | undefined;

  const store: CredentialStore = {
    tokenByMandate: (id) => raw.tokenByMandate(id),
    tokenByRef: (ref) => raw.tokenByRef(ref),
    putToken: (rec) => raw.putToken(rec),
    async credentialByOrder(agent_code, mandate_id, order_ref) {
      if (forceNew === orderKey(agent_code, mandate_id, order_ref)) return undefined;
      return raw.credentialByOrder(agent_code, mandate_id, order_ref);
    },
    async putCredential(rec) {
      const key = orderKey(rec.agent_code, rec.mandate_id, rec.order_ref);
      if (forceNew !== key) return raw.putCredential(rec);
      // Криптограмма детерминирована (токен-сервис стенда): те же значения и тот же срок — та же криптограмма. Второй
      // реквизит с чужой криптограммой не пишется — обычный повтор (прежний реквизит), сбой не сработал.
      const ck = cryptogramKey(rec.token_ref, rec.cryptogram_sha256);
      const prior = await raw.credentialByOrder(rec.agent_code, rec.mandate_id, rec.order_ref);
      if (!prior || extraByCryptogram.has(ck) || (await raw.credentialByCryptogram(rec.token_ref, rec.cryptogram_sha256))) {
        return prior ?? raw.putCredential(rec);
      }
      extra.set(rec.credential_ref, structuredClone(rec));
      extraByCryptogram.set(ck, rec.credential_ref);
      faults.markCall("Н-02");
      faults.fired("Н-02", "SECOND_CREDENTIAL_ISSUED", { mandate_id: rec.mandate_id, merchant_id: rec.merchant_id, order_ref: rec.order_ref });
      return structuredClone(rec);
    },
    async credentialByRef(credential_ref, agent_code) {
      const c = extra.get(credential_ref);
      if (c) return c.agent_code === agent_code ? structuredClone(c) : undefined;
      return raw.credentialByRef(credential_ref, agent_code);
    },
    async credentialForMerchant(credential_ref, merchant_id) {
      const c = extra.get(credential_ref);
      if (c) return c.merchant_id === merchant_id ? structuredClone(c) : undefined;
      return raw.credentialForMerchant(credential_ref, merchant_id);
    },
    async credentialByCryptogram(token_ref, sha) {
      const ref = extraByCryptogram.get(cryptogramKey(token_ref, sha));
      const c = ref === undefined ? undefined : extra.get(ref);
      return c ? structuredClone(c) : raw.credentialByCryptogram(token_ref, sha);
    },
    async consume(credential_ref, op_ref) {
      const c = extra.get(credential_ref);
      if (!c) return raw.consume(credential_ref, op_ref);
      if (c.status !== "ISSUED") return false;
      extra.set(credential_ref, { ...c, status: "USED", op_ref });
      return true;
    },
  };

  const wrap = (credentials: Credentials): Credentials =>
    new Proxy(credentials, {
      get(target, prop) {
        if (prop === "issue") {
          const issue: Credentials["issue"] = async (agent_code, req, beforeWrite) => {
            // Только новый запрос по уже выданному заказу; первый запрос и повтор под ключом (replay) — как обычно.
            const prior = faults.armed("Н-02") && (await raw.credentialByOrder(agent_code, req.mandate_id, req.order_ref));
            if (!prior) return target.issue(agent_code, req, beforeWrite);
            forceNew = orderKey(agent_code, req.mandate_id, req.order_ref);
            try {
              return await target.issue(agent_code, req, beforeWrite);
            } finally {
              forceNew = undefined;
            }
          };
          return issue;
        }
        const v: unknown = Reflect.get(target, prop, target);
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    });

  return { store, wrap };
}
