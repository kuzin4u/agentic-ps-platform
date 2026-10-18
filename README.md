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

Текущая версия — **v0.5.0** (лента событий, подписка и push-доставка, PS-08). Что изменилось и что ломает — в
[`CHANGELOG.md`](CHANGELOG.md). Стенд и фикстуры подключаются по тегу:

```
npm i -D "agentic-ps-platform@git+https://github.com/kuzin4u/agentic-ps-platform.git#v0.5.0"
```

`createStand()` из `agentic-ps-platform/stand`, фикстуры — `agentic-ps-platform/fixtures`.
