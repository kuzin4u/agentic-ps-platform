-- П9 Попытки push-доставки событий агенту (РП40 п. 5, PS-08 К1.3в). Изменяемая таблица, отдельно от pao_events:
-- лента остаётся «только вставка», состояние доставки меняется здесь. Строка создаётся в транзакции события
-- (РП39 п. 1), если агент ACTIVE и подписан на тип; иначе push по событию не будет — только лента.

-- attempts растёт до отправки (взятие строки обработчиком): сбой после отправки повторяет тот же event_id —
-- «не менее одного раза» (инвариант 9). next_at_ms — когда строку можно взять: срок повтора или конец аренды попытки.
-- claims — номер взятия, только растёт: итог пишет только последний взявший (attempts при возврате попытки повторяется).
CREATE TABLE pao_event_deliveries (
  event_id    text     PRIMARY KEY REFERENCES pao_events (event_id),
  agent_code  text     NOT NULL,
  state       text     NOT NULL CHECK (state IN ('PENDING', 'DELIVERED', 'EXHAUSTED', 'SKIPPED')),
  attempts    integer  NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  claims      integer  NOT NULL DEFAULT 0 CHECK (claims >= 0),
  next_at_ms  bigint   NOT NULL,
  last_reason text
);

CREATE INDEX pao_event_deliveries_due ON pao_event_deliveries (next_at_ms) WHERE state = 'PENDING';
