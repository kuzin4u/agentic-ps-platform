# agentic-ps-platform

Агентная платформа платёжной системы: реестр агентов, журнал согласий, сервис состояния бюджета, точка решения в пути авторизации, агентские реквизиты, подтверждение на нейтральной поверхности, споры. Интерфейсы с процессингом (ПИ-1–ПИ-9) и Протокол агентских операций (ПАО v1) для агентов покупателя. Эмуляторы окружения для песочницы.

- Правила и инварианты — [`CLAUDE.md`](CLAUDE.md)
- Документы — [`docs/core/INDEX.md`](docs/core/INDEX.md)
- Архитектура — [`docs/core/ARCHITECTURE.md`](docs/core/ARCHITECTURE.md)

## Запуск

```
npm ci
npm test            # модульные тесты и сценарии
npm run check       # проверка типов
npm run lint
npm run build && npm start   # сервер на 127.0.0.1:8080, GET /health
npm run dev                  # то же с перезапуском при изменениях
```

Среда — переменная `PLATFORM_ENV`: `dev` (по умолчанию, всё в памяти, без базы) или `sandbox`. Порт — `PORT`.

Песочница: `docker compose up -d` поднимает PostgreSQL 16 (`postgres`/`postgres`, база `platform` — стендовые значения).

Рабочий сервер доставляет события агентам по подписке (PS-08): хосты адресов подписки задаются
`event_subscription_allow_hosts` в файле параметров (`PARAMS_PATH`); пустой список закрывает подписку всем.

## Версии и стенд для агента

Текущая версия — **v0.35.0** (тестовый банк-участник песочницы `npm run participant` — keygen, sign / revoke по ПИ-8, `docs/deploy/sandbox.md` §9а; сервер и ответы агенту не меняются; ПАО — по-прежнему 1.4.0; Р-1031). Подробности —
[`CHANGELOG.md`](CHANGELOG.md). Стенд и фикстуры подключаются по тегу:

```
npm i -D "agentic-ps-platform@git+https://github.com/kuzin4u/agentic-ps-platform.git#v0.35.0"
```

`createStand()` из `agentic-ps-platform/stand`, фикстуры — `agentic-ps-platform/fixtures`. Журнал обращений стенда —
`stand.calls()` (`source` `network` / `inject`, без тел), выданные пары реквизита для теста утечки — `stand.issuedCredentials()`
(РП25, дополнение STAND-69). Способы оплаты витрин эмулятора продавцов — `createMerchants(stand, { paymentMethods: { "MER-1042": ["cash"] } })`:
замена по `merchant_id`, `[]` допустим, неизвестный `merchant_id` — исключение (РП25, дополнение #86).
