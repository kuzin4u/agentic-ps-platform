-- П6 Подтверждение человеком (PS-19 ч. 1, РП50): запрос подтверждения на итоговые значения и однократная ссылка.
-- Номера карты нет (инвариант 1). Строки не удаляются; переходы — только по РП50 п. 5, ключевые поля не меняются.
CREATE TABLE confirmations (
  confirmation_id  text PRIMARY KEY
                   CHECK (confirmation_id ~ '^cnf_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  agent_code       text NOT NULL CHECK (agent_code <> ''),
  mandate_id       text NOT NULL CHECK (mandate_id <> ''),
  merchant_id      text NOT NULL CHECK (merchant_id <> ''),
  amount           bigint NOT NULL CHECK (amount >= 1),
  currency         char(3) NOT NULL,
  order_ref        text NOT NULL CHECK (order_ref <> ''),
  split_detected   boolean NOT NULL,
  status           text NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'USED')),
  -- Часы Платформы, toISOString(): одна длина и формат — строки сравниваются по порядку времени.
  created_at       text NOT NULL,
  expires_at       text NOT NULL CHECK (expires_at > created_at),
  confirmation_ref text UNIQUE CHECK (confirmation_ref ~ '^cr_[a-z2-7]{26}$'),
  -- Решение участника (ПИ-8, РП50 п. 4): запись и подпись банка — доказательство подтверждения человеком.
  participant_code text,
  kid              text,
  decision         text CHECK (decision IN ('APPROVE', 'REJECT')),
  totals_hash      char(64) CHECK (totals_hash ~ '^[0-9a-f]{64}$'),
  decided_at       text,
  signature        text,
  op_ref           text,
  -- Ссылка есть ровно у одобренных (APPROVED, USED); решение — у них и у REJECTED; op_ref — только у USED.
  CHECK ((confirmation_ref IS NOT NULL) = (status IN ('APPROVED', 'USED'))),
  CHECK ((decision IS NOT NULL) = (status IN ('APPROVED', 'USED', 'REJECTED'))),
  CHECK ((decision = 'APPROVE') = (status IN ('APPROVED', 'USED')) OR decision IS NULL),
  CHECK ((decision IS NULL) = (participant_code IS NULL) AND (decision IS NULL) = (kid IS NULL)
         AND (decision IS NULL) = (totals_hash IS NULL) AND (decision IS NULL) = (decided_at IS NULL)
         AND (decision IS NULL) = (signature IS NULL)),
  CHECK ((op_ref IS NOT NULL) = (status = 'USED'))
);

-- Один запрос в ожидании на ключ (РП50 п. 2): одновременное CONFIRMATION_REQUIRED с двух экземпляров — одна строка.
CREATE UNIQUE INDEX confirmations_pending_key ON confirmations (mandate_id, merchant_id, order_ref, amount, currency)
  WHERE status = 'PENDING';
-- Поиск по ключу (п. 9: после EXPIRED, REJECTED, USED нового запроса нет).
CREATE INDEX confirmations_key ON confirmations (mandate_id, merchant_id, order_ref, amount, currency);

CREATE FUNCTION confirmations_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'confirmations: удаление запрещено' USING ERRCODE = 'restrict_violation';
  END IF;
  IF (NEW.confirmation_id, NEW.agent_code, NEW.mandate_id, NEW.merchant_id, NEW.amount, NEW.currency, NEW.order_ref,
      NEW.split_detected, NEW.created_at, NEW.expires_at)
     IS DISTINCT FROM
     (OLD.confirmation_id, OLD.agent_code, OLD.mandate_id, OLD.merchant_id, OLD.amount, OLD.currency, OLD.order_ref,
      OLD.split_detected, OLD.created_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'confirmations: итоговые значения не меняются' USING ERRCODE = 'restrict_violation';
  END IF;
  -- Переходы РП50 п. 5: из PENDING — решение или истечение; из APPROVED — только погашение с той же ссылкой и решением.
  IF NOT (
       (OLD.status = 'PENDING' AND NEW.status IN ('APPROVED', 'REJECTED', 'EXPIRED'))
    OR (OLD.status = 'APPROVED' AND NEW.status = 'USED'
        AND (NEW.confirmation_ref, NEW.participant_code, NEW.kid, NEW.decision, NEW.totals_hash, NEW.decided_at, NEW.signature)
            IS NOT DISTINCT FROM
            (OLD.confirmation_ref, OLD.participant_code, OLD.kid, OLD.decision, OLD.totals_hash, OLD.decided_at, OLD.signature))
  ) THEN
    RAISE EXCEPTION 'confirmations: переход % → % запрещён', OLD.status, NEW.status USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER confirmations_guard BEFORE UPDATE OR DELETE ON confirmations
  FOR EACH ROW EXECUTE FUNCTION confirmations_guard();

CREATE TRIGGER confirmations_no_truncate BEFORE TRUNCATE ON confirmations
  FOR EACH STATEMENT EXECUTE FUNCTION confirmations_guard();

-- Вставка — только запрос в ожидании, без решения и ссылки.
CREATE FUNCTION confirmations_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status <> 'PENDING' THEN
    RAISE EXCEPTION 'confirmations: вставка — только PENDING' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER confirmations_insert_guard BEFORE INSERT ON confirmations
  FOR EACH ROW EXECUTE FUNCTION confirmations_insert_guard();
