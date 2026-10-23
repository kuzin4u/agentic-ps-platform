-- П9 Лента: четвёртый источник — смена статуса допуска агента (РП54 п. 8, PS-17): agent.suspended / agent.reinstated без
-- записи журнала согласий. agent_status_version — row_version записи реестра после смены: одна смена — одно событие,
-- повтор действия оператора событие не удваивает (РП54 п. 2). Строки до миграции не меняются.
ALTER TABLE pao_events ADD COLUMN agent_status_version bigint NULL CHECK (agent_status_version >= 2);
ALTER TABLE pao_events DROP CONSTRAINT pao_events_one_source;
ALTER TABLE pao_events ADD CONSTRAINT pao_events_one_source CHECK (
  (journal_chain IS NOT NULL AND journal_seq IS NOT NULL AND confirmation_id IS NULL AND op_ref IS NULL
    AND agent_status_version IS NULL
    AND type NOT LIKE 'confirmation.%' AND type NOT LIKE 'operation.%' AND type NOT LIKE 'agent.%')
  OR (journal_chain IS NULL AND journal_seq IS NULL AND confirmation_id IS NOT NULL AND op_ref IS NULL
    AND agent_status_version IS NULL AND type LIKE 'confirmation.%')
  OR (journal_chain IS NULL AND journal_seq IS NULL AND confirmation_id IS NULL AND op_ref IS NOT NULL
    AND agent_status_version IS NULL AND type LIKE 'operation.%')
  OR (journal_chain IS NULL AND journal_seq IS NULL AND confirmation_id IS NULL AND op_ref IS NULL
    AND agent_status_version IS NOT NULL AND type IN ('agent.suspended', 'agent.reinstated'))
);

-- На смену статуса — одно событие (РП54 п. 2): второе по той же версии записи агента не встаёт.
ALTER TABLE pao_events ADD CONSTRAINT pao_events_agent_status UNIQUE (agent_code, agent_status_version);
