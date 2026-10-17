-- П2 Журнал согласий (PS-06 К1.2). Записи журнала — в core_journal ядра (001_journal.sql), цепочка на корневой мандат.
-- Здесь — две таблицы при журнале, обе только для вставки (инвариант 6). Номера миграций Платформы — с 100:
-- учёт общий с ядром (core_migrations, по имени файла), имена не пересекаются с 001–099 ядра.

-- Индекс «мандат → цепочка и агент»: GET находит цепочку и отдаёт мандат только своему агенту. id — UUID v4 (прежние)
-- или v8 (вычисляемый от агента и ключа идемпотентности, РП33 доп.). Статуса здесь нет:
-- статус — свёртка записей журнала при чтении. Строка без записи MANDATE_REQUESTED в журнале — мандата нет.
CREATE TABLE consent_mandates (
  id         text PRIMARY KEY CHECK (id ~ '^mnd_[0-9a-f]{8}-[0-9a-f]{4}-[48][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  chain      text NOT NULL CHECK (chain ~ '^consent:mnd_'),
  agent_code text NOT NULL,
  created_at text NOT NULL,
  -- sha256(canonicalJson(реквизиты перечня)): сверка прерванной записи с повтором тем же ключом (РП33 доп. п. 7).
  terms_hash char(64) NOT NULL CHECK (terms_hash ~ '^[0-9a-f]{64}$')
);

-- Предмет мандата и соль обязательства: в журнале только subject_commitment = sha256(canonicalJson({salt, subject, cart})).
-- Без соли короткий предмет подбирается по хэшу. Предмет — вероятно, персональные данные (состав покупок): удаление
-- соли и предмета по сроку или требованию клиента — отдельной задачей через /decision (STATUS «Открыто»).
CREATE TABLE consent_subjects (
  mandate_id   text PRIMARY KEY REFERENCES consent_mandates (id),
  salt         text NOT NULL CHECK (salt ~ '^[A-Za-z0-9_-]{43}$'),
  subject_json text NOT NULL
);

CREATE FUNCTION consent_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '%: только добавление, % запрещён', TG_TABLE_NAME, TG_OP USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER consent_mandates_no_update_delete
  BEFORE UPDATE OR DELETE ON consent_mandates
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER consent_mandates_no_truncate
  BEFORE TRUNCATE ON consent_mandates
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER consent_subjects_no_update_delete
  BEFORE UPDATE OR DELETE ON consent_subjects
  FOR EACH ROW EXECUTE FUNCTION consent_append_only();
CREATE TRIGGER consent_subjects_no_truncate
  BEFORE TRUNCATE ON consent_subjects
  FOR EACH STATEMENT EXECUTE FUNCTION consent_append_only();
