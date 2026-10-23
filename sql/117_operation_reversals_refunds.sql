-- П8 Реверсал, истечение авторизации и возврат (PS-16 ч. 3, РП55 п. 1, 3, 6). Записи — по ПИ-3 REVERSAL / AUTH_EXPIRED
-- и REFUND, одна на op_ref, только вставка (как sql/115). Формирует Платформа по сообщению процессинга (инвариант 5).
-- Номера карты и token_ref нет (инвариант 1). Без внешнего ключа на adp_operations: он закрыл бы TRUNCATE раньше триггеров
-- (как sql/114, sql/115).

-- Реверсал и истечение авторизации (РП55 п. 1): удержания записи операции освобождены до записи; события нет до ПАО 1.5.0.
CREATE TABLE operation_reversals (
  op_ref     text PRIMARY KEY CHECK (op_ref <> ''),
  kind       text NOT NULL CHECK (kind IN ('REVERSAL', 'AUTH_EXPIRED')),
  -- Агент по домену токена из записи ADP; NULL — не установлен.
  agent_code text CHECK (agent_code <> ''),
  mandate_id text CHECK (mandate_id <> ''),
  at         text NOT NULL
);

CREATE TRIGGER operation_reversals_no_update_delete
  BEFORE UPDATE OR DELETE ON operation_reversals
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER operation_reversals_no_truncate
  BEFORE TRUNCATE ON operation_reversals
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();

-- Возврат (РП55 п. 3): после записи об исполнении; бюджет не восстанавливается (restore_budget_on_refund = false, РП9);
-- operation.refunded — в транзакции записи. Один возврат на op_ref; несколько — PS-23.
CREATE TABLE operation_refunds (
  op_ref     text PRIMARY KEY CHECK (op_ref <> ''),
  agent_code text CHECK (agent_code <> ''),
  mandate_id text CHECK (mandate_id <> ''),
  -- Сумма — минимальные единицы парой с валютой (правило совместимости 2); больше суммы клиринга — записывается (п. 3).
  amount     bigint NOT NULL CHECK (amount >= 1),
  currency   char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  at         text NOT NULL
);

CREATE TRIGGER operation_refunds_no_update_delete
  BEFORE UPDATE OR DELETE ON operation_refunds
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER operation_refunds_no_truncate
  BEFORE TRUNCATE ON operation_refunds
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();

-- Список операций по мандату (РП55 п. 6): GET /pao/v1/operations?mandate_id — по времени решения.
CREATE INDEX adp_operations_mandate ON adp_operations (mandate_id, at) WHERE mandate_id IS NOT NULL;
