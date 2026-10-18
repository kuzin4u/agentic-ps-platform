-- П9 Лента событий агенту (РП39, PS-08 К1.2): Outbox в транзакции записи журнала согласий. Только вставка: состояние
-- доставки (попытки push, К1.3) — в отдельной таблице, событие не меняется.

-- Событие — от записи журнала: внешний ключ не пускает событие без записи, одна транзакция не оставляет запись без
-- события. seq — номер у агента без пропусков: выдаётся под pg_advisory_xact_lock агента, поэтому N + 1 фиксируется
-- только после N, и курсор after не проскакивает незафиксированное событие (РП39 п. 2).
CREATE TABLE pao_events (
  agent_code    text    NOT NULL,
  seq           bigint  NOT NULL CHECK (seq >= 1),
  event_id      text    NOT NULL UNIQUE
                CHECK (event_id ~ '^evt_[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  type          text    NOT NULL,
  at            text    NOT NULL,
  -- canonicalJson({mandate_id}): ни предмета, ни сумм, ни статуса (A7 п. 8.3, РП39 п. 5).
  data          text    NOT NULL,
  journal_chain text    NOT NULL,
  journal_seq   bigint  NOT NULL,
  PRIMARY KEY (agent_code, seq),
  UNIQUE (journal_chain, journal_seq),
  FOREIGN KEY (journal_chain, journal_seq) REFERENCES core_journal (chain, seq)
);

CREATE TRIGGER pao_events_no_update_delete
  BEFORE UPDATE OR DELETE ON pao_events
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER pao_events_no_truncate
  BEFORE TRUNCATE ON pao_events
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();
