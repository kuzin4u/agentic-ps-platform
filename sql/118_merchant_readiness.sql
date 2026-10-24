-- П10 Знак готовности продавца (PS-30 ч. 2 К1, A5 п. 5, РП57 п. 2): записи эквайрера (ACTIVE / WITHDRAWN, подписанная
-- запись ПИ-8) и оператора (SUSPENDED с причиной / REINSTATED), только вставка. Порядок — seq (bigserial), не issued_at и
-- не часы сервера. Статус — в два шага: последняя запись оператора SUSPENDED → SUSPENDED; иначе по последней записи
-- эквайрера. Номера карты нет (инвариант 1).
CREATE TABLE merchant_readiness (
  seq              bigserial PRIMARY KEY,
  merchant_id      text NOT NULL CHECK (merchant_id <> '' AND length(merchant_id) <= 128),
  source           text NOT NULL CHECK (source IN ('ACQUIRER', 'OPERATOR')),
  status           text NOT NULL,
  -- Причина приостановления (A5 п. 5.3) — только у SUSPENDED оператора.
  reason           text,
  -- Подписанная запись эквайрера: у оператора — NULL.
  participant_code text,
  kid              text,
  readiness_ref    text,
  issued_at        text,
  -- Ed25519 эквайрера над canonicalJson записи с меткой pao:participant-merchant-readiness:v1, base64url.
  signature        text,
  -- Часы Платформы при записи.
  received_at      text NOT NULL,
  CHECK (
    -- coalesce: NULL в CHECK — «пройдено», а запись эквайрера без любого из полей — не запись.
    (source = 'ACQUIRER' AND status IN ('ACTIVE', 'WITHDRAWN') AND reason IS NULL
      AND coalesce(participant_code, '') <> '' AND coalesce(kid, '') <> '' AND coalesce(readiness_ref, '') ~ '^[A-Za-z0-9_-]{1,64}$'
      AND coalesce(issued_at, '') <> '' AND coalesce(signature, '') ~ '^[A-Za-z0-9_-]{86}$')
    OR
    (source = 'OPERATOR'
      AND ((status = 'SUSPENDED' AND coalesce(reason, '') IN ('DISCREPANCY', 'AGENT_REFUSALS', 'SYSTEMATIC_CANCELLATION'))
           OR (status = 'REINSTATED' AND reason IS NULL))
      AND participant_code IS NULL AND kid IS NULL AND readiness_ref IS NULL AND issued_at IS NULL AND signature IS NULL)
  ),
  -- readiness_ref уникален у участника навсегда (РП57 п. 2); у записей оператора NULL — не сравниваются.
  UNIQUE (participant_code, readiness_ref)
);

-- Последняя запись продавца по источнику (статус и проверка приостановления при вставке).
CREATE INDEX merchant_readiness_last ON merchant_readiness (merchant_id, source, seq DESC);

CREATE FUNCTION merchant_readiness_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'merchant_readiness: только вставка (РП57 п. 2)' USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER merchant_readiness_guard BEFORE UPDATE OR DELETE ON merchant_readiness
  FOR EACH ROW EXECUTE FUNCTION merchant_readiness_guard();

-- TRUNCATE строчные триггеры не вызывает — отдельный, на оператор (как participant_limits).
CREATE TRIGGER merchant_readiness_no_truncate BEFORE TRUNCATE ON merchant_readiness
  FOR EACH STATEMENT EXECUTE FUNCTION merchant_readiness_guard();
