-- П10 Лимиты клиента от банка (PS-20 К1.2, РП45 п. 1, 3): подписанные записи банка с версией, только вставка; действует
-- наибольшая версия пары (participant_code, principal_ref). Запись — как прислал банк (подпись — над её canonicalJson),
-- история — доказательство. Номера карты нет — только principal_ref (инвариант 1).
CREATE TABLE participant_limits (
  participant_code text   NOT NULL CHECK (participant_code <> ''),
  principal_ref    text   NOT NULL CHECK (principal_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
  version          bigint NOT NULL CHECK (version >= 1),
  kid              text   NOT NULL CHECK (kid <> ''),
  -- Limits ПИ-8: суммы — целые ≥ 0 в минимальных единицах, парой с currency (правило совместимости 2).
  limits           jsonb  NOT NULL CHECK (jsonb_typeof(limits) = 'object'),
  issued_at        text   NOT NULL,
  -- Ed25519 банка над canonicalJson записи с меткой pao:participant-limits:v1, base64url.
  signature        text   NOT NULL CHECK (signature <> ''),
  -- Часы Платформы при записи.
  received_at      text   NOT NULL,
  PRIMARY KEY (participant_code, principal_ref, version)
);

CREATE FUNCTION participant_limits_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'participant_limits: только вставка (РП45 п. 1)' USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER participant_limits_guard BEFORE UPDATE OR DELETE ON participant_limits
  FOR EACH ROW EXECUTE FUNCTION participant_limits_guard();

-- TRUNCATE строчные триггеры не вызывает — отдельный, на оператор (как adp_operations).
CREATE TRIGGER participant_limits_no_truncate BEFORE TRUNCATE ON participant_limits
  FOR EACH STATEMENT EXECUTE FUNCTION participant_limits_guard();
