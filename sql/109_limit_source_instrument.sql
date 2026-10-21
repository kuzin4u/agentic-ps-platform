-- PS-14 ч. 3 (РП49 (е)): чей предел у LIMIT_EXCEEDED — ещё и инструмента (amount_max реквизита), client.limit_declined
-- с reason INSTRUMENT. Новой миграцией, а не правкой sql/107: миграции учитываются по имени файла, на развёрнутой базе
-- правка 107 не применилась бы. Записи до обновления — limit_source NULL у отказа по инструменту (уведомление без reason).
ALTER TABLE adp_operations
  DROP CONSTRAINT adp_operations_limit_source_check,
  ADD CONSTRAINT adp_operations_limit_source_check CHECK (limit_source IN ('MANDATE', 'CLIENT', 'INSTRUMENT'));
