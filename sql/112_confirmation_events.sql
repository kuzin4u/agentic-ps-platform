-- П9 Лента событий агенту, второй источник (РП51 п. 1–4, PS-19 ч. 2): переход запроса подтверждения П6 даёт событие
-- confirmation.* без записи журнала согласий. Номер seq — общий у агента с событиями мандатов (блокировка агента, РП39 п. 2).
-- Таблица остаётся «только вставка» (триггеры sql/101); строки до миграции не меняются: у них пара журнала.

ALTER TABLE pao_events ALTER COLUMN journal_chain DROP NOT NULL;
ALTER TABLE pao_events ALTER COLUMN journal_seq DROP NOT NULL;
ALTER TABLE pao_events ADD COLUMN confirmation_id text NULL;

-- Ровно один источник: пара журнала (внешний ключ и UNIQUE sql/101 прежние) либо запрос подтверждения с типом
-- confirmation.*. Внешнего ключа на confirmations нет: событие пишется в транзакции перехода, порядок вставки — там.
ALTER TABLE pao_events ADD CONSTRAINT pao_events_one_source CHECK (
  (journal_chain IS NOT NULL AND journal_seq IS NOT NULL AND confirmation_id IS NULL AND type NOT LIKE 'confirmation.%')
  OR (journal_chain IS NULL AND journal_seq IS NULL AND confirmation_id IS NOT NULL AND type LIKE 'confirmation.%')
);

-- На один переход — одно событие (РП51 п. 2): второе событие того же типа по запросу не встаёт.
ALTER TABLE pao_events ADD CONSTRAINT pao_events_confirmation_type UNIQUE (confirmation_id, type);
