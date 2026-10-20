-- П2/П10 Порядок пары клиента (PS-20 ч. 2 К1.3, РП46 (а)): подписи мандатов (SIGN) и метки отзыва всех полномочий
-- (REVOKE_ALL) пары (participant_code, principal_ref) с номером n в паре. Номер выдаётся под pg_advisory_xact_lock пары
-- в транзакции записи — порядок n = порядок фиксации, часы не участвуют. Только вставка (инвариант 6).
-- Мандат пары отозван меткой, если есть REVOKE_ALL с n больше n его SIGN (у CART — SIGN корня). Номера карты нет (инвариант 1).
CREATE TABLE principal_order (
  participant_code text   NOT NULL CHECK (participant_code <> ''),
  principal_ref    text   NOT NULL CHECK (principal_ref <> ''),
  n                bigint NOT NULL CHECK (n >= 1),
  kind             text   NOT NULL CHECK (kind IN ('SIGN', 'REVOKE_ALL')),
  -- SIGN — mandate_id, REVOKE_ALL — revocation_ref банка.
  ref              text   NOT NULL CHECK (ref <> ''),
  -- Часы Платформы при записи — для журнала, в правиле не участвуют.
  at               text   NOT NULL,
  -- REVOKE_ALL — запись банка с подписью (pao:participant-principal-revocation:v1), canonicalJson; SIGN — NULL.
  record           text,
  PRIMARY KEY (participant_code, principal_ref, n),
  UNIQUE (participant_code, principal_ref, kind, ref),
  CHECK ((kind = 'REVOKE_ALL') = (record IS NOT NULL))
);

CREATE FUNCTION principal_order_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'principal_order: только вставка (РП46 (а))' USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER principal_order_guard BEFORE UPDATE OR DELETE ON principal_order
  FOR EACH ROW EXECUTE FUNCTION principal_order_guard();

CREATE TRIGGER principal_order_no_truncate BEFORE TRUNCATE ON principal_order
  FOR EACH STATEMENT EXECUTE FUNCTION principal_order_guard();
