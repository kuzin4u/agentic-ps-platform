-- П1 Сертификаты mTLS агентов и список отзыва (РП27 п. 4, РП65 п. 3, SEC-1-код ч. 1): рядом с записью агента, запись —
-- в транзакции допуска вместе с агентом и первым ключом. Строки не удаляются; отзыв необратим — revoked_at. Закрытых ключей
-- здесь нет: ключ сертификата — у оператора агента, ключ УЦ — файл на постоянном томе (РП65 п. 4).
CREATE TABLE agent_certificates (
  -- Серийный номер — 16 байт в hex нижнего регистра (РП65 п. 2).
  serial      text PRIMARY KEY CHECK (serial ~ '^[0-9a-f]{32}$'),
  agent_code  text NOT NULL REFERENCES agents (agent_code),
  -- Сертификат, DER в канонической base64.
  der         text NOT NULL,
  not_before  timestamptz NOT NULL,
  not_after   timestamptz NOT NULL CHECK (not_after > not_before),
  revoked_at  timestamptz NULL,
  created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX agent_certificates_agent ON agent_certificates (agent_code);
