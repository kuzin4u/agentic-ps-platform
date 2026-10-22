-- П6 Выбор инструмента человеком (РП51 п. 13, PS-19 ч. 3): instrument_chosen — CARD | SBP (канонический channel; номера
-- карты и счёта нет — инвариант 1) из записи решения ПИ-8. От UPK обязателен, от банка — по желанию; есть только у решения.
-- Строки до миграции не меняются: у них решения без инструмента (NULL).
ALTER TABLE confirmations ADD COLUMN instrument_chosen text CHECK (instrument_chosen IN ('CARD', 'SBP'));
ALTER TABLE confirmations ADD CONSTRAINT confirmations_instrument_with_decision CHECK (instrument_chosen IS NULL OR decision IS NOT NULL);

-- Триггер sql/111 с инструментом: погашение APPROVED → USED не меняет ни ссылку, ни решение, ни выбранный инструмент.
CREATE OR REPLACE FUNCTION confirmations_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
