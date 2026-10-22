-- П8 Итог операции и события operation.* (PS-16 ч. 1, РП52): факты операции в записи ADP, таблица итогов «только
-- вставка», третий источник ленты агенту. Номера карты и token_ref нет (инвариант 1).

-- Факты операции — тем же UPDATE решения, что decision (РП52 п. 9): новых обращений к базе в пути ADP нет. Заполняются
-- у записи «в работе» и решением не меняются (триггер sql/103). agent_code (sql/107) — агент по домену токена (п. 5):
-- пишется и без клиента мандата. Сумма — msg_amount парой с msg_currency (правило совместимости 2): amount и currency
-- sql/104 — столбцы окна дробления, заполняются только при входе в окно.
ALTER TABLE adp_operations
  ADD COLUMN order_ref    text CHECK (order_ref <> ''),
  ADD COLUMN channel      text CHECK (channel IN ('CARD', 'SBP')),
  ADD COLUMN merchant_id  text CHECK (merchant_id <> ''),
  ADD COLUMN msg_amount   bigint CHECK (msg_amount >= 1),
  ADD COLUMN msg_currency char(3) CHECK (msg_currency ~ '^[A-Z]{3}$'),
  -- Признак сообщения как пришёл (A1 п. 5.1): код агента, мандат, ссылка на запись об исполнении — только ссылки.
  ADD COLUMN aoi          jsonb CHECK (aoi IS NULL OR jsonb_typeof(aoi) = 'object'),
  ADD CONSTRAINT adp_operations_msg_money_whole CHECK ((msg_amount IS NULL) = (msg_currency IS NULL));

-- Проход сборщика итогов — по решённым отказам и CONFIRMATION_REQUIRED в горизонте operation_outcome_horizon_sec
-- (РП52 п. 1 (а), «Дополнения» п. 1).
CREATE INDEX adp_operations_outcome ON adp_operations (at)
  WHERE decision IS NOT NULL AND decision->>'decision' IN ('DECLINE', 'CONFIRMATION_REQUIRED');

-- Итог операции (РП52 п. 8): один на op_ref, только вставка; источник — сборщик по решению ADP или ПИ-3 ответ эмитента.
-- Без внешнего ключа на adp_operations: он закрыл бы TRUNCATE adp_operations раньше её триггера (как sql/107).
CREATE TABLE operation_outcomes (
  op_ref     text PRIMARY KEY CHECK (op_ref <> ''),
  -- Агент по домену токена; NULL — агент не установлен (РП52 п. 5): итог есть, события нет.
  agent_code text CHECK (agent_code <> ''),
  status     text NOT NULL CHECK (status IN ('AUTHORIZED', 'DECLINED', 'CONFIRMATION_REQUIRED')),
  reason     text CHECK (reason <> ''),
  source     text NOT NULL CHECK (source IN ('ADP', 'ISSUER')),
  at         text NOT NULL,
  CONSTRAINT operation_outcomes_reason CHECK ((status = 'AUTHORIZED') = (reason IS NULL))
);

CREATE TRIGGER operation_outcomes_no_update_delete
  BEFORE UPDATE OR DELETE ON operation_outcomes
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER operation_outcomes_no_truncate
  BEFORE TRUNCATE ON operation_outcomes
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();

-- П9 Лента: третий источник — итог операции (РП52 п. 7). Ровно один источник: пара журнала, запрос подтверждения с типом
-- confirmation.* или op_ref с типом operation.*. Строки до миграции не меняются.
ALTER TABLE pao_events ADD COLUMN op_ref text NULL CHECK (op_ref <> '');
ALTER TABLE pao_events DROP CONSTRAINT pao_events_one_source;
ALTER TABLE pao_events ADD CONSTRAINT pao_events_one_source CHECK (
  (journal_chain IS NOT NULL AND journal_seq IS NOT NULL AND confirmation_id IS NULL AND op_ref IS NULL
    AND type NOT LIKE 'confirmation.%' AND type NOT LIKE 'operation.%')
  OR (journal_chain IS NULL AND journal_seq IS NULL AND confirmation_id IS NOT NULL AND op_ref IS NULL AND type LIKE 'confirmation.%')
  OR (journal_chain IS NULL AND journal_seq IS NULL AND confirmation_id IS NULL AND op_ref IS NOT NULL AND type LIKE 'operation.%')
);

-- На итог — одно событие (РП52 п. 7): второе событие того же типа по операции не встаёт.
ALTER TABLE pao_events ADD CONSTRAINT pao_events_operation_type UNIQUE (op_ref, type);
