-- П10 Метаданные пакета агентской оплаты (PS-30 ч. 2 К2, РП22 п. 6, РП57 п. 5): подписанные записи эквайрера за продавца,
-- только вставка; порядок — seq. Только для сверки credential_ref → op_ref и отчётности (П11): ADP их не читает. Номера
-- карты, суммы и криптограммы нет (инварианты 1, 5); aoi — только agent_code и mandate_id.
CREATE TABLE payment_metadata (
  seq              bigserial PRIMARY KEY,
  participant_code text NOT NULL CHECK (participant_code <> ''),
  kid              text NOT NULL CHECK (kid <> ''),
  merchant_id      text NOT NULL CHECK (merchant_id <> '' AND length(merchant_id) <= 128),
  metadata_ref     text NOT NULL CHECK (metadata_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
  credential_ref   text NOT NULL CHECK (credential_ref <> '' AND length(credential_ref) <= 128),
  order_ref        text NOT NULL CHECK (order_ref <> '' AND length(order_ref) <= 128),
  -- Признак из пакета, если эквайрер его получил (РП22 п. 6); без поддержки aoi — NULL.
  -- Ровно два строковых поля: подзапрос в CHECK недопустим, лишние ключи — вычитанием.
  aoi              jsonb CHECK (aoi IS NULL OR (jsonb_typeof(aoi) = 'object'
                                                AND jsonb_typeof(aoi -> 'agent_code') = 'string'
                                                AND jsonb_typeof(aoi -> 'mandate_id') = 'string'
                                                AND aoi - 'agent_code' - 'mandate_id' = '{}'::jsonb)),
  submitted_at     text NOT NULL CHECK (submitted_at <> ''),
  -- Ed25519 эквайрера над canonicalJson записи с меткой pao:participant-payment-metadata:v1, base64url.
  signature        text NOT NULL CHECK (signature ~ '^[A-Za-z0-9_-]{86}$'),
  -- Часы Платформы при записи.
  received_at      text NOT NULL,
  -- metadata_ref уникален у участника навсегда (РП57 п. 5, как readiness_ref).
  UNIQUE (participant_code, metadata_ref)
);

-- Последняя запись метаданных реквизита у продавца (GET …/payments/{credential_ref}).
CREATE INDEX payment_metadata_last ON payment_metadata (merchant_id, credential_ref, seq DESC);

CREATE FUNCTION payment_metadata_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'payment_metadata: только вставка (РП57 п. 5)' USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER payment_metadata_guard BEFORE UPDATE OR DELETE ON payment_metadata
  FOR EACH ROW EXECUTE FUNCTION payment_metadata_guard();

-- TRUNCATE строчные триггеры не вызывает — отдельный, на оператор.
CREATE TRIGGER payment_metadata_no_truncate BEFORE TRUNCATE ON payment_metadata
  FOR EACH STATEMENT EXECUTE FUNCTION payment_metadata_guard();
