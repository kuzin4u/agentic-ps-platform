-- П8 Запись об исполнении (PS-16 ч. 2, РП53 п. 1, 8): по ПИ-3 PRESENTMENT, одна на op_ref, только вставка; событие
-- operation.settled — в той же транзакции (третий источник ленты sql/114). Формирует Платформа по сообщению процессинга
-- (A1 п. 6.2, инвариант 5). Номера карты и token_ref нет (инвариант 1).
-- Без внешнего ключа на adp_operations и operation_outcomes: он закрыл бы TRUNCATE раньше их триггеров (как sql/114).
CREATE TABLE fulfilments (
  op_ref            text PRIMARY KEY CHECK (op_ref <> ''),
  -- ful_ + 24 шестнадцатеричных знака SHA-256: не длиннее 32 символов — под aoi.fulfilment_ref (ПИ-2, [альбом]).
  fulfilment_ref    text NOT NULL UNIQUE CHECK (fulfilment_ref ~ '^ful_[0-9a-f]{24}$'),
  -- Агент по домену токена; NULL — агент не установлен: запись есть, события нет (РП53 п. 9).
  agent_code        text CHECK (agent_code <> ''),
  mandate_id        text CHECK (mandate_id <> ''),
  order_ref         text CHECK (order_ref <> ''),
  merchant_id       text CHECK (merchant_id <> ''),
  -- Суммы — минимальные единицы парой с валютой (правило совместимости 2).
  authorized_amount bigint NOT NULL CHECK (authorized_amount >= 1),
  final_amount      bigint NOT NULL CHECK (final_amount >= 1),
  currency          char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  scope_check       text NOT NULL CHECK (scope_check IN ('WITHIN_LIMITS', 'EXCEEDS_AUTHORIZATION', 'NOT_RESERVED')),
  -- Закреплено по мандату записи операции после закрепления (РП53 п. 8).
  spent_position    bigint NOT NULL CHECK (spent_position >= 0),
  at                text NOT NULL
);

CREATE TRIGGER fulfilments_no_update_delete
  BEFORE UPDATE OR DELETE ON fulfilments
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER fulfilments_no_truncate
  BEFORE TRUNCATE ON fulfilments
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();
