-- П5 Агентские реквизиты (PS-14 ч. 1, РП47 п. 10): токен на CART и реквизит на заказ. Номера карты и значения
-- криптограммы нет (инвариант 1): у токена — funding_ref банка, у реквизита — SHA-256 криптограммы.
CREATE TABLE agent_tokens (
  token_ref      text PRIMARY KEY CHECK (token_ref <> ''),
  agent_code     text NOT NULL CHECK (agent_code <> ''),
  -- Один токен на CART (РП47 п. 2): одновременный выпуск с двух экземпляров — одна строка.
  mandate_id     text NOT NULL UNIQUE CHECK (mandate_id <> ''),
  merchant_scope jsonb NOT NULL CHECK (jsonb_typeof(merchant_scope) = 'array'),
  valid_to       text NOT NULL,
  funding_ref    text NOT NULL CHECK (funding_ref <> ''),
  created_at     text NOT NULL
);

CREATE TABLE agent_credentials (
  credential_ref    text PRIMARY KEY CHECK (credential_ref <> ''),
  agent_code        text NOT NULL,
  mandate_id        text NOT NULL,
  token_ref         text NOT NULL REFERENCES agent_tokens (token_ref),
  order_ref         text NOT NULL CHECK (order_ref <> ''),
  merchant_id       text NOT NULL CHECK (merchant_id <> ''),
  amount_max        bigint NOT NULL CHECK (amount_max >= 1),
  currency          char(3) NOT NULL,
  valid_to          text NOT NULL,
  cryptogram_sha256 char(64) NOT NULL CHECK (cryptogram_sha256 ~ '^[0-9a-f]{64}$'),
  status            text NOT NULL CHECK (status IN ('ISSUED', 'USED')),
  -- Операция, погасившая реквизит (РП47 п. 8); у ISSUED — NULL, у USED — обязательна.
  op_ref            text CHECK ((status = 'ISSUED') = (op_ref IS NULL)),
  created_at        text NOT NULL,
  -- Повтор заказа — тот же реквизит (РП47 п. 5).
  UNIQUE (agent_code, mandate_id, order_ref),
  -- Поиск в ADP п. 4 (РП47 п. 7).
  UNIQUE (token_ref, cryptogram_sha256)
);

-- Погашение однократно: USED назад в ISSUED не возвращается, ключевые поля не меняются, строки не удаляются.
CREATE FUNCTION agent_credentials_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'agent_credentials: удаление запрещено' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.status <> 'ISSUED' OR NEW.status <> 'USED'
     OR (NEW.credential_ref, NEW.agent_code, NEW.mandate_id, NEW.token_ref, NEW.order_ref, NEW.merchant_id, NEW.amount_max,
         NEW.currency, NEW.valid_to, NEW.cryptogram_sha256, NEW.created_at)
        IS DISTINCT FROM
        (OLD.credential_ref, OLD.agent_code, OLD.mandate_id, OLD.token_ref, OLD.order_ref, OLD.merchant_id, OLD.amount_max,
         OLD.currency, OLD.valid_to, OLD.cryptogram_sha256, OLD.created_at) THEN
    RAISE EXCEPTION 'agent_credentials: только погашение ISSUED → USED' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER agent_credentials_guard BEFORE UPDATE OR DELETE ON agent_credentials
  FOR EACH ROW EXECUTE FUNCTION agent_credentials_guard();

CREATE TRIGGER agent_credentials_no_truncate BEFORE TRUNCATE ON agent_credentials
  FOR EACH STATEMENT EXECUTE FUNCTION agent_credentials_guard();
