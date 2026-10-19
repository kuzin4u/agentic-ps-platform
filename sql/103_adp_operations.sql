-- П4 Запись операции ADP (PS-10 К2.1, РП43 п. 5, доп. п. 16): op_ref → решение и удержания. Строка создаётся «в работе»
-- (decision IS NULL) условной вставкой до резерва — к резерву по op_ref проходит только первый запрос, в том числе с
-- другого экземпляра. Решение записывается один раз; решённую строку не меняют и не удаляют. BYPASS не пишется.
CREATE TABLE adp_operations (
  op_ref     text PRIMARY KEY CHECK (op_ref <> ''),
  -- sha256(canonicalJson(сообщение без ts и seq)) — повтор с другим сообщением — инцидент (доп. РП43 п. 17).
  msg_hash   char(64) NOT NULL CHECK (msg_hash ~ '^[0-9a-f]{64}$'),
  -- Ответ ADP (ПИ-1 Decision); NULL — «в работе» или решение не сохранено.
  decision   jsonb,
  mandate_id text,
  -- hold.id по каждому счёту в порядке резерва: CART, затем родитель (РП43 п. 6).
  holds      jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(holds) = 'array'),
  at         text NOT NULL
);

CREATE FUNCTION adp_operations_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'adp_operations: удаление запрещено' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.decision IS NOT NULL OR NEW.op_ref <> OLD.op_ref OR NEW.msg_hash <> OLD.msg_hash OR NEW.at <> OLD.at THEN
    RAISE EXCEPTION 'adp_operations: решённая запись и ключевые поля не меняются' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER adp_operations_guard BEFORE UPDATE OR DELETE ON adp_operations
  FOR EACH ROW EXECUTE FUNCTION adp_operations_guard();
