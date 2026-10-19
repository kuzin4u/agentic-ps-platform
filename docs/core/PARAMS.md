# Стендовые параметры Платформы

Значения из `config/params.stand.json` — настройки песочницы, а не нормы и не нормативы процессинга. В коде — только из конфигурации.

Файл задаётся переменной окружения `PARAMS_PATH` (по умолчанию `config/params.stand.json` от корня пакета Платформы, а не от текущего каталога, — РП25). Нет ключа, лишний ключ, неверный тип или нарушенная граница — отказ запуска, значений по умолчанию нет (РП20).

| Ключ | Стенд | Смысл | Чем закрывается |
|---|---|---|---|
| `adp_p99_ms` / `adp_timeout_ms` | 50 / 150 | Задержка точки решения и таймаут процессинга | нормативы ОПКЦ, нагрузочный прогон |
| `bypass_overhead_ms` | 1 | Добавка к неагентским операциям | нагрузочный прогон |
| `adp_availability_target` | 99,95 % | Цель песочницы | нормативы оператора |
| `revocation_propagation_max_ms` | 1 000 | Отзыв ключа или мандата до ADP и шлюза | прогон (A7 п. 6.3 «без задержки») |
| `reservation_ttl_sec` | 7 дней | Жизнь резерва без клиринга: `expires_at` удержания; освобождение — проход `expire` раз в 60 с (РП41 п. 6). Должен быть не меньше срока подтверждения авторизации банком — параметра пока нет, вопрос к PS-07 (STATUS «Открыто») | правила ПС о сроке авторизации |
| `event_reorder_window_ms` / `event_retry_max` | 5 000 / 8 | Порядок событий и доставка агенту | прогон |
| `event_page_max` | 100 | Не больше стольких событий в одном ответе ленты `GET /pao/v1/events` (РП39 п. 7); дальше — следующий запрос с `after` | прогон |
| `event_delivery_timeout_ms` | 5 000 | Тайм-аут одной попытки push-доставки события: разрешение имени, соединение, отправка, статус ответа — один предел (РП40 доп. п. 10); тело ответа не читается (РП40 п. 4) | прогон |
| `event_subscription_allow_hosts` | `["agent-emulator.stand"]` | Разрешённые хосты адреса подписки `PUT /pao/v1/subscription` — точное имя DNS, без масок. Пустой список — подписка запрещена всем (РП40 п. 2); в бою — из соглашения участника (PS-20) | соглашение участника |
| `cryptogram_ttl_sec` | 900 | Срок одноразовой криптограммы | прогон, токен-сервис |
| `order_hold_sec` | 900 | Ожидание подтверждения | прогон (A7 п. 7.2) |
| `confirm_above_kop` | 300 000 | Рыночный порог подтверждения, в копейках RUB (пара `{amount, currency: "RUB"}`, РП44 п. 5): сумма выше — подтверждение; действует меньшее из него и клиентского `Limits.confirm_above` (с PS-20); операция не в RUB — `STATE_UNAVAILABLE` | данные пилота (В2, Р6) |
| `split_window_sec` / `split_min_ops` | 600 / 2 | Выявление дробления (РП44 п. 1): операция не выше порога — доля, если в окне `split_window_sec` по корневому INTENT вместе с ней не меньше `split_min_ops` одобренных операций и их сумма выше порога | данные пилота (К10, O19) |
| `signature_skew_sec` | 300 | Окно подписи ПАО | прогон |
| `unavailable_retry_after_sec` | 1 | `Retry-After` у ответов ПАО 503 (`UPSTREAM_UNAVAILABLE`, `STATE_UNAVAILABLE`) | прогон (РП24) |
| `merchant_rate_limit_per_min` | 6 000 | Лимит обращений к витринам эмулятора продавцов с одного адреса в минуту (все маршруты `/v1`); превышение — 429 `RATE_LIMITED` с `Retry-After`. На стенде щедрый: тесты агента не упираются | прогон песочницы для сторонних агентов (PS-26) |
| `idempotency_ttl_sec` | 86 400 | Срок хранения результата по `Idempotency-Key` ПАО (пара «агент + ключ»): повтор в этот срок возвращает прежний ответ (РП30) | прогон; публикация агентам — `/.well-known/pao-configuration` (ПАО 1.5.0, РП37) |
| `pao_rate_limit_per_30s` | 3 000 | Грубый лимит обращений к шлюзу ПАО с одного адреса за окно 30 с (все маршруты `/pao`, до проверки подписи); превышение — 429 `RATE_LIMITED` с `Retry-After` ≤ 30 (окно 30 с — граница РП24). На стенде щедрый (≈ 6 000 в минуту): тесты агента не упираются. Лимит по уровню агента — отдельно (РП32 п. 6) | прогон песочницы для сторонних агентов (PS-26) |
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
| Целые ≥ 1: `adp_p99_ms`, `adp_timeout_ms`, `revocation_propagation_max_ms`, `reservation_ttl_sec`, `cryptogram_ttl_sec`, `order_hold_sec`, `confirm_above_kop`, `split_window_sec`, `signature_skew_sec`, `key_ttl_days`, `qualified_signature_above_kop`, `qualified_signature_above_days`, `cx_outcome_timeout_days`, `protocol_overlap_days`, `event_retry_max`, `event_page_max`, `event_delivery_timeout_ms`, `merchant_rate_limit_per_min`, `pao_rate_limit_per_30s` | ноль вырождает механизм (РП20: `protocol_overlap_days`, `event_retry_max`) |
| Целые ≥ 0: `bypass_overhead_ms`, `event_reorder_window_ms`, `key_overlap_days` | ноль допустим |
| `split_min_ops` ≥ 2 | дробление — от двух операций |
| `aoi_rollout_phase` ∈ 1…3 | A1 п. 8.3 |
| `adp_availability_target` — строка «N%», 0 < N ≤ 100 | |
| `bypass_overhead_ms` < `adp_p99_ms` | РП4, РП20 |
| `adp_timeout_ms` > `adp_p99_ms` | ПИ §3, РП20 |
| `key_overlap_days` < `key_ttl_days` | перекрытие ключей короче их жизни |
| `idempotency_ttl_sec` — целое ≥ 60 | не меньше аренды захвата ключа ядра (60 с, условие К6 agentic-core: аренда ≤ ttl; РП30 п. 3) |
| `unavailable_retry_after_sec` — целое 0…30 | 0 — «повторить сразу» (ПАО `minimum: 0`); верхняя граница — `maxRetryAfterSec` клиента ПАО agentic-core (30): больший `Retry-After` эталонный клиент отвергает (РП24) |
| `event_subscription_allow_hosts` — массив имён DNS в нижнем регистре (метки `a-z0-9-`, не IP), без повторов; пустой допустим | пустой — fail-closed: подписка запрещена всем (РП40 п. 2) |

## Журнал изменений

| Дата | Ключ | Было | Стало | Основание |
|---|---|---|---|---|
| 08.10.2026 | все | — | стенд | первичная конфигурация |
| 11.10.2026 | `unavailable_retry_after_sec` | — | 1 | РП24, аудит PS-04 №2 |
| 13.10.2026 | `merchant_rate_limit_per_min` | — | 6 000 | PS-12, CodeQL №82 `js/missing-rate-limiting`; решение владельца (РП29) |
| 15.10.2026 | `idempotency_ttl_sec` | — | 86 400 | PS-05, Ш16; решение владельца (РП30) |
| 16.10.2026 | `pao_rate_limit_per_30s` | — | 3 000 | PS-05, CodeQL №81 `js/missing-rate-limiting`, Ш12; решение владельца (РП32) |
| 18.10.2026 | `event_page_max` | — | 100 | PS-08 К1.2, лента `GET /pao/v1/events`; решение владельца (РП39 п. 7) |
| 18.10.2026 | `event_delivery_timeout_ms` | — | 5 000 | PS-08 К1.3а, push-доставка событий; решение владельца (РП40 п. 4) |
| 18.10.2026 | `event_subscription_allow_hosts` | — | `["agent-emulator.stand"]` | PS-08 К1.3а, SSRF адреса подписки; решение владельца (РП40 п. 2, 8) |
