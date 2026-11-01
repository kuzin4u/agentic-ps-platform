-- П8 Несколько возвратов по операции (PS-23 ч. 1, РП71 п. 1–3, нюансы 1–3): refund_ref — ссылка возврата у процессинга
-- из канонического REFUND ПИ-3. NULL — прежняя форма (один возврат на op_ref, РП55 п. 3); непустая строка — запись на
-- пару (op_ref, refund_ref). Прежние записи остаются с refund_ref = NULL. Только вставка — триггеры sql/117 прежние.
-- Смешение форм по одной операции и событие только у первого возврата — под pg_advisory_xact_lock по op_ref в
-- транзакции записи (нюанс 2, src/fulfilment/refunds.ts); уникальный индекс ниже — второй барьер.
-- Внешних ключей на operation_refunds нет; имя первичного ключа — по умолчанию (PRIMARY KEY в столбце, sql/117).
ALTER TABLE operation_refunds ADD COLUMN refund_ref text CHECK (refund_ref <> '');
ALTER TABLE operation_refunds DROP CONSTRAINT operation_refunds_pkey;
-- Снятие первичного ключа NOT NULL не снимает, но явно — чтобы не зависеть от версии.
ALTER TABLE operation_refunds ALTER COLUMN op_ref SET NOT NULL;
-- Один индекс на обе формы (нюанс 3): NULLS NOT DISTINCT (PostgreSQL ≥ 15; стенд, CI и песочница — 16) — (op_ref, NULL)
-- не больше одного, (op_ref, refund_ref) — по одному на ссылку; op_ref — первый столбец, WHERE op_ref = $1 идёт по индексу.
CREATE UNIQUE INDEX operation_refunds_op_ref_key ON operation_refunds (op_ref, refund_ref) NULLS NOT DISTINCT;
