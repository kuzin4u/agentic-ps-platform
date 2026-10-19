-- П4 Окно дробления (PS-13, РП44 п. 4): столбцы окна в записи операции ADP. Вход — транзакцией под
-- pg_advisory_xact_lock ключа окна: чтение числа и суммы окна после блокировки, запись своей строки «в работе», COMMIT.
-- В окне — одобрения и записи «в работе», вошедшие в окно; отказ решением убирает строку фильтром (РП44 п. 2).
ALTER TABLE adp_operations
  -- Корневой INTENT: у INTENT — он сам, у CART — родитель (РП44 п. 3).
  ADD COLUMN window_key   text CHECK (window_key <> ''),
  -- Сумма операции в минимальных единицах — парой с валютой (правило совместимости 2).
  ADD COLUMN amount       bigint CHECK (amount >= 1),
  ADD COLUMN currency     char(3) CHECK (currency ~ '^[A-Z]{3}$'),
  -- Часы Платформы (now() ADP), мс от эпохи.
  ADD COLUMN window_at_ms bigint CHECK (window_at_ms >= 0),
  ADD CONSTRAINT adp_operations_window_whole CHECK (
    (window_key IS NULL AND amount IS NULL AND currency IS NULL AND window_at_ms IS NULL)
    OR (window_key IS NOT NULL AND amount IS NOT NULL AND currency IS NOT NULL AND window_at_ms IS NOT NULL)
  );

CREATE INDEX adp_operations_window ON adp_operations (window_key, window_at_ms) WHERE window_key IS NOT NULL;

-- Тот же триггер (sql/103): решённую запись и ключевые поля не меняют; столбцы окна заполняются один раз из NULL у
-- записи «в работе» и решением не меняются (РП44 п. 4).
CREATE OR REPLACE FUNCTION adp_operations_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'adp_operations: удаление запрещено' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.decision IS NOT NULL OR NEW.op_ref <> OLD.op_ref OR NEW.msg_hash <> OLD.msg_hash OR NEW.at <> OLD.at THEN
    RAISE EXCEPTION 'adp_operations: решённая запись и ключевые поля не меняются' USING ERRCODE = 'restrict_violation';
  END IF;
  IF (NEW.window_key, NEW.amount, NEW.currency, NEW.window_at_ms) IS DISTINCT FROM
     (OLD.window_key, OLD.amount, OLD.currency, OLD.window_at_ms)
     AND (OLD.window_key IS NOT NULL OR NEW.decision IS NOT NULL) THEN
    RAISE EXCEPTION 'adp_operations: столбцы окна заполняются один раз у записи «в работе»' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

-- Вставка — только «в работе» без окна (доп. РП44 п. 2, /audit PS-13 № 5): решение и столбцы окна при INSERT запрещены,
-- иначе строка обошла бы «один раз из NULL у записи в работе». Код Платформы вставляет только op_ref, msg_hash, at.
CREATE FUNCTION adp_operations_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.decision IS NOT NULL OR NEW.window_key IS NOT NULL OR NEW.amount IS NOT NULL OR NEW.currency IS NOT NULL
     OR NEW.window_at_ms IS NOT NULL THEN
    RAISE EXCEPTION 'adp_operations: вставка только «в работе» без решения и окна' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER adp_operations_insert_guard BEFORE INSERT ON adp_operations
  FOR EACH ROW EXECUTE FUNCTION adp_operations_insert_guard();
