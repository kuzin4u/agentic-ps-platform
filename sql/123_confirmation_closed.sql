-- П6 Закрытие запроса Платформой после отзыва мандата (РП76 п. 3): PENDING → REJECTED без записи решения банка, с
-- closed_reason из закрытого перечня и closed_at по часам Платформы. Отклонение человеком (ПИ-8) — как прежде, с записью
-- решения и без closed_reason. Строки до миграции не меняются: у них closed_reason и closed_at — NULL.
ALTER TABLE confirmations
  ADD COLUMN closed_reason text CHECK (closed_reason IN ('MANDATE_REVOKED')),
  ADD COLUMN closed_at     text CHECK (closed_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$');

-- Ограничение sql/111 «решение есть ровно у APPROVED, USED и REJECTED» снимается: у закрытого Платформой REJECTED решения
-- нет. Имя у него автоматическое — ищется по определению; ровно одно (STRICT), иначе миграция падает.
DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO STRICT c FROM pg_constraint
   WHERE conrelid = 'confirmations'::regclass AND contype = 'c'
     AND pg_get_constraintdef(oid) LIKE '%decision IS NOT NULL%'
     AND pg_get_constraintdef(oid) LIKE '%REJECTED%';
  EXECUTE format('ALTER TABLE confirmations DROP CONSTRAINT %I', c);
END
$$;

ALTER TABLE confirmations
  -- Причина и момент закрытия — заданы оба или ни один; только у REJECTED.
  ADD CONSTRAINT confirmations_closed_pair CHECK ((closed_reason IS NULL) = (closed_at IS NULL)),
  ADD CONSTRAINT confirmations_closed_rejected CHECK (closed_reason IS NULL OR status = 'REJECTED'),
  -- Запись решения обязательна у APPROVED, USED и у REJECTED без closed_reason; запрещена, если closed_reason задан.
  ADD CONSTRAINT confirmations_decision_or_closed
    CHECK ((decision IS NOT NULL) = (status IN ('APPROVED', 'USED') OR (status = 'REJECTED' AND closed_reason IS NULL)));
