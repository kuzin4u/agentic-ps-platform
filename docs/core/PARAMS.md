# Стендовые параметры Платформы

Значения из `config/params.stand.json` — настройки песочницы, а не нормы и не нормативы процессинга. В коде — только из конфигурации.

Файл задаётся переменной окружения `PARAMS_PATH` (по умолчанию `config/params.stand.json`). Нет ключа, лишний ключ, неверный тип или нарушенная граница — отказ запуска, значений по умолчанию нет (РП20).

| Ключ | Стенд | Смысл | Чем закрывается |
|---|---|---|---|
| `adp_p99_ms` / `adp_timeout_ms` | 50 / 150 | Задержка точки решения и таймаут процессинга | нормативы ОПКЦ, нагрузочный прогон |
| `bypass_overhead_ms` | 1 | Добавка к неагентским операциям | нагрузочный прогон |
| `adp_availability_target` | 99,95 % | Цель песочницы | нормативы оператора |
| `revocation_propagation_max_ms` | 1 000 | Отзыв ключа или мандата до ADP и шлюза | прогон (A7 п. 6.3 «без задержки») |
| `reservation_ttl_sec` | 7 дней | Жизнь резерва без клиринга | правила ПС о сроке авторизации |
| `event_reorder_window_ms` / `event_retry_max` | 5 000 / 8 | Порядок событий и доставка агенту | прогон |
| `cryptogram_ttl_sec` | 900 | Срок одноразовой криптограммы | прогон, токен-сервис |
| `order_hold_sec` | 900 | Ожидание подтверждения | прогон (A7 п. 7.2) |
| `confirm_above_kop` | 300 000 | Порог подтверждения | данные пилота (В2, Р6) |
| `split_window_sec` / `split_min_ops` | 600 / 2 | Выявление дробления | данные пилота (К10) |
| `signature_skew_sec` | 300 | Окно подписи ПАО | прогон |
| `key_ttl_days` / `key_overlap_days` | 90 / 7 | Ключи агентов | O02 |
| `qualified_signature_above_*` | 50 000 ₽ / 30 дней | Усиленная подпись мандата | юридическая оценка (O08, Р9) |
| `restore_budget_on_refund` | false | Восстановление бюджета при возврате | юридическая оценка (В8, РП9) |
| `aoi_rollout_phase` | 3 | Очередь внедрения признака | A1 п. 8.3 |
| `protocol_overlap_days` | 180 | Параллельная работа версий ПАО | решение владельца |
| `issuer_mode_default` | ON_BEHALF | Режим эмитента по умолчанию | РП3 |
| `cx_outcome_timeout_days` | 30 | Срок, за который поставщик условного исполнения сообщает итог сделки | договор с ПУИ |

## Границы

| Правило | Почему |
|---|---|
| Целые ≥ 1: `adp_p99_ms`, `adp_timeout_ms`, `revocation_propagation_max_ms`, `reservation_ttl_sec`, `cryptogram_ttl_sec`, `order_hold_sec`, `confirm_above_kop`, `split_window_sec`, `signature_skew_sec`, `key_ttl_days`, `qualified_signature_above_kop`, `qualified_signature_above_days`, `cx_outcome_timeout_days`, `protocol_overlap_days`, `event_retry_max` | ноль вырождает механизм (РП20: `protocol_overlap_days`, `event_retry_max`) |
| Целые ≥ 0: `bypass_overhead_ms`, `event_reorder_window_ms`, `key_overlap_days` | ноль допустим |
| `split_min_ops` ≥ 2 | дробление — от двух операций |
| `aoi_rollout_phase` ∈ 1…3 | A1 п. 8.3 |
| `adp_availability_target` — строка «N%», 0 < N ≤ 100 | |
| `bypass_overhead_ms` < `adp_p99_ms` | РП4, РП20 |
| `adp_timeout_ms` > `adp_p99_ms` | ПИ §3, РП20 |
| `key_overlap_days` < `key_ttl_days` | перекрытие ключей короче их жизни |

## Журнал изменений

| Дата | Ключ | Было | Стало | Основание |
|---|---|---|---|---|
| 08.10.2026 | все | — | стенд | первичная конфигурация |
