-- П10 Уведомления клиента через банк (PS-20 ч. 3, РП46 (б), доп. п. 7, 9; A3 п. 5.3): Outbox участника, отметка разбора
-- записей операций уведомителем, попытки вебхука; признаки уведомителя в записи операции ADP. Номера карты нет (инвариант 1).

-- Признаки для уведомителя — тем же UPDATE решения, что decision (РП46 доп. п. 9 (о1)): новых обращений к базе в пути
-- ADP нет. Заполняются у записи «в работе» и решением не меняются (триггер sql/103).
ALTER TABLE adp_operations
  -- Клиент мандата — банк подписи корня и principal_ref (РП45 п. 1); NULL — мандат не прочитан или без клиента.
  ADD COLUMN participant_code  text CHECK (participant_code <> ''),
  ADD COLUMN principal_ref     text CHECK (principal_ref <> ''),
  ADD COLUMN agent_code        text CHECK (agent_code <> ''),
  -- Чей предел у LIMIT_EXCEEDED (РП46 доп. п. 7): мандат (в том числе родитель CART) или лимит клиента.
  ADD COLUMN limit_source      text CHECK (limit_source IN ('MANDATE', 'CLIENT')),
  -- Счёт периода клиента и остаток после резерва (ADP уже читает его в leftOf) — для client.limit_exhausted.
  ADD COLUMN client_account    text CHECK (client_account <> ''),
  ADD COLUMN client_left_after bigint CHECK (client_left_after >= 0),
  ADD CONSTRAINT adp_operations_principal_whole CHECK ((participant_code IS NULL) = (principal_ref IS NULL)),
  ADD CONSTRAINT adp_operations_client_left_whole CHECK (client_left_after IS NULL OR client_account IS NOT NULL);

-- Проход уведомителя — по решённым записям в горизонте participant_notify_horizon_sec (РП46 доп. п. 9 (о2)).
CREATE INDEX adp_operations_notify ON adp_operations (at)
  WHERE decision IS NOT NULL AND participant_code IS NOT NULL;

-- Outbox участника (РП46 (б) п. 1). seq — номер у участника без пропусков: выдаётся под pg_advisory_xact_lock участника,
-- поэтому N + 1 фиксируется только после N, и курсор after ленты не проскакивает незафиксированное (как pao_events, РП39 п. 2).
-- notification_id — из типа и ключа повтора (операция, мандат, счёт периода, revocation_ref): второе уведомление на то же
-- событие невозможно (UNIQUE), в том числе с другого экземпляра.
CREATE TABLE participant_notifications (
  participant_code text   NOT NULL CHECK (participant_code <> ''),
  seq              bigint NOT NULL CHECK (seq >= 1),
  notification_id  text   NOT NULL UNIQUE
                   CHECK (notification_id ~ '^ntf_[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  type             text   NOT NULL CHECK (type IN (
                     'client.mandate_first_use', 'client.mandate_exhausted', 'client.limit_exhausted',
                     'client.limit_declined', 'client.revoked_all')),
  at               text   NOT NULL,
  -- canonicalJson: только principal_ref, mandate_id, agent_code, op_ref, revocation_ref и коды (правило совместимости 3).
  data             text   NOT NULL,
  PRIMARY KEY (participant_code, seq)
);

CREATE TRIGGER participant_notifications_no_update_delete
  BEFORE UPDATE OR DELETE ON participant_notifications
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER participant_notifications_no_truncate
  BEFORE TRUNCATE ON participant_notifications
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();

-- Отметка разбора записи операции уведомителем — в той же транзакции, что её уведомления: запись разобрана целиком или нет.
-- Без внешнего ключа на adp_operations: он закрыл бы TRUNCATE adp_operations раньше её триггера (К3.1а; запрет очистки
-- проверяется триггером sql/103). op_ref берётся только из прочитанной записи операции.
CREATE TABLE participant_notify_seen (
  op_ref text PRIMARY KEY CHECK (op_ref <> ''),
  at     text NOT NULL
);

CREATE TRIGGER participant_notify_seen_no_update_delete
  BEFORE UPDATE OR DELETE ON participant_notify_seen
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER participant_notify_seen_no_truncate
  BEFORE TRUNCATE ON participant_notify_seen
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();

-- Попытки вебхука-сигнала участнику (РП46 (б) п. 3; как pao_event_deliveries, РП40 п. 5, доп. п. 6–8). Изменяемая, отдельно
-- от Outbox. Строка создаётся в транзакции уведомления на каждое уведомление; у участника без notify_url — SKIPPED при первом
-- взятии (адрес — из записи участника на момент отправки, как подписка агента, РП40 доп. п. 11).
CREATE TABLE participant_notification_deliveries (
  notification_id  text    PRIMARY KEY REFERENCES participant_notifications (notification_id),
  participant_code text    NOT NULL,
  state            text    NOT NULL CHECK (state IN ('PENDING', 'DELIVERED', 'EXHAUSTED', 'SKIPPED')),
  attempts         integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  claims           integer NOT NULL DEFAULT 0 CHECK (claims >= 0),
  next_at_ms       bigint  NOT NULL,
  last_reason      text
);

CREATE INDEX participant_notification_deliveries_due ON participant_notification_deliveries (next_at_ms) WHERE state = 'PENDING';
