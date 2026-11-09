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

Текущая версия — **v0.44.0** (отзыв мандата закрывает ожидающие запросы подтверждения — РП76: `revoke`, `revoke-all`, `relinquish` дают `REJECTED` и `confirmation.rejected`; миграция `sql/123`; агенту и ядру обязательного нет; ПАО — по-прежнему 1.4.0). Подробности —
[`CHANGELOG.md`](CHANGELOG.md). Стенд и фикстуры подключаются по тегу:

```
npm i -D "agentic-ps-platform@git+https://github.com/kuzin4u/agentic-ps-platform.git#v0.44.0"
```

`createStand()` из `agentic-ps-platform/stand`, фикстуры — `agentic-ps-platform/fixtures`. Журнал обращений стенда —
`stand.calls()` (`source` `network` / `inject`, `agent_code` — у обращений, допущенных шлюзом ПАО, без тел), выданные пары реквизита для теста утечки — `stand.issuedCredentials()`
(РП25, дополнение STAND-69). Способы оплаты витрин эмулятора продавцов — `createMerchants(stand, { paymentMethods: { "MER-1042": ["cash"] } })`:
замена по `merchant_id`, `[]` допустим, неизвестный `merchant_id` — исключение (РП25, дополнение #86).

Свой набор витрин — параметром стенда (РП25, дополнение #106): набор заменяет фикстуру целиком, из него строятся справочник
продавцов, эквайрер, знаки готовности и витрины `createMerchants`; при создании набор сверяется по правилам (а)–(е),
неверная витрина — исключение, стенд не создаётся.

```ts
import { SHOPS, type Shop } from "agentic-ps-platform/fixtures";
import { createMerchants, createStand } from "agentic-ps-platform/stand";

const bakery: Shop = { id: "SHOP-9001", merchant_id: "MER-9001", /* … */ readiness_mark: true, behaviour: "NORMAL", items: [/* … */] };
const stand = createStand({ shops: [...SHOPS, bakery] }); // только свои витрины — { shops: [bakery] }
const merchants = createMerchants(stand); // витрины — stand.shops
```

Демо-стенд для пульта DEMO-2 (РП75, #112) — режим сбоев и действия кнопок реакции, только в демо-стенде приложения
(не в песочнице и не в пилоте): `createStand({ demo: { faults: true } })` даёт `stand.demo` — `arm` / `disarm` сбоев
вида «П» (Н-02…Н-05, Н-11, Н-12), `mark` нарушений вида «ПР», `log()`, действия `stopPurchase`, `remindClient`,
`revokeMandate`, `sendToReview`; срок подтверждения и удержания заказа — `demo_order_hold_sec` (45 с). Без `demo` поля
`stand.demo` нет. Подробности и коды — CHANGELOG v0.43.0 и DECISIONS РП75.
