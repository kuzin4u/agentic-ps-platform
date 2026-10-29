# Песочница на VPS: установка и приёмка

Инструкция для развёртывания песочницы Платформы v0.32.1 на своём VPS и приёмки с Mac владельца командой `npm run acceptance` (SANDBOX-ACC, решение владельца от 28.10.2026). Основания: РП65 (сертификат агента по CSR), РП66 (TLS 1.3 в процессе, ступень 0, ключ УЦ из файла), РП67 (`PAO_TRUSTED_PROXIES` пустой), РП42 п. 4 (журнал запуска).

Имена ниже даны по умолчанию. Если меняете их, передайте те же значения в `npm run acceptance` параметрами `--root`, `--env-file`, `--unit`, `--user`.

| Что | Значение по умолчанию |
|---|---|
| Каталог установки | `/opt/agentic-ps-platform` |
| Пользователь сервиса | `agentic` (без входа в систему) |
| Unit systemd | `agentic-platform` |
| Файл переменных (EnvironmentFile) | `/etc/agentic-platform/env` |
| Файл ключа УЦ | `/var/lib/agentic-platform/sandbox-ca` |
| Порт | `8443` |
| ssh-пользователь владельца | `owner` (подставьте свой) |
| Адрес песочницы (пример) | `sandbox.agentic-comm.ru` — VPS в Yandex Cloud |

## 0. Почему VPS, а не Render

TLS завершается в самом процессе Платформы: только TLS 1.3, сертификат сервера выдаёт УЦ песочницы, клиентский сертификат агента проверяется на ступени 0 (РП66). Прокси L7, который сам завершает TLS (так работает Render), не передаст процессу сертификат агента, и ступень 0 станет невозможна. Перед процессом допустим только прокси L4 (TCP) или вообще никакого. `PAO_TRUSTED_PROXIES` оставляйте пустым: с непустым списком sandbox не запустится (`STARTUP_PROXIES_INVALID`, `TLS_IN_PROCESS`, РП67).

## 1. VPS и порт

- Ubuntu 24.04 LTS — инструкция написана под неё (пути sudoers — `/usr/bin/node`, `secure_path`, `/usr/bin/sh` — по документации Ubuntu и NodeSource); на живой ВМ команды ещё не запускались, проверка — при установке ≈ 02.11. Публичный IP; DNS-имя — по желанию.
- **Yandex Cloud** (схема создания ВМ, решение владельца 29.10):
  - группа безопасности ВМ: входящие — только 22/tcp и 8443/tcp; исходящие — любые (нужны для `npm ci` и обновлений). `ufw` ниже — второй слой, группа безопасности его не заменяет;
  - статический IP — в той же зоне доступности, что ВМ (адрес зональный);
  - ВМ не прерываемая: прерываемую облако останавливает, и песочница пропадает;
  - гарантированная доля vCPU — 100 % (2 vCPU, 4 ГБ). При меньшей доле приёмка ловит ложные тайм-ауты;
  - образ Ubuntu 24.04 LTS, вход по SSH-ключу (не OS Login), логин — не root.
- Открыты только порты 22 (ssh) и 8443 (Платформа):
  ```
  sudo ufw allow 22/tcp && sudo ufw allow 8443/tcp && sudo ufw enable
  ```
- Никакого HTTP на других портах (80, nginx и т. п.): приёмка проверяет только порт сервиса (проверка 4). Открытый HTTP где-то ещё она не увидит, поэтому сверьте вручную, что слушается только `:22` и `:8443`:
  ```
  sudo ss -ltnp
  ```
- Node.js 22 из NodeSource, чтобы `node` лежал в `/usr/bin/node`. Этот путь входит в `secure_path` sudo, от него зависит программа приёмки.
  ```
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs git
  node -v   # v22.x, не ниже 20.19
  ```

## 2. База PostgreSQL 16 со своим паролем

```
sudo apt-get install -y postgresql-16
PGPASS=$(openssl rand -hex 24)
sudo -u postgres psql -c "CREATE ROLE agentic_platform LOGIN PASSWORD '$PGPASS';"
sudo -u postgres psql -c "CREATE DATABASE agentic_platform OWNER agentic_platform;"
echo "$PGPASS"   # сохраните в менеджер паролей; дальше — только в EnvironmentFile
```

- База слушает только `127.0.0.1`, как в PostgreSQL по умолчанию; наружу её не открывать.
- Пароль генерируется в hex, чтобы в `DATABASE_URL` не понадобилось экранирование.
- Миграции применяет сам процесс при запуске (самопроверка `db.migrations`).

## 3. Пользователь сервиса и v0.32.1

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin agentic
sudo git clone --branch v0.32.1 --depth 1 https://github.com/kuzin4u/agentic-ps-platform.git /opt/agentic-ps-platform
cd /opt/agentic-ps-platform && sudo npm ci
```

- `npm ci` ставит зависимости ровно по lock-файлу и собирает `dist` (шаг `prepare`). Ядро `@kuzin4u/agentic-core` берётся по `git+https`.
- Код принадлежит root, сервис его только читает.
- Установку для приёмки не меняйте: программа допуска приходит по ssh во временный каталог и удаляется после работы (раздел 8).

## 4. Ключ УЦ: `ca:init` (один раз)

```
sudo install -d -o agentic -g agentic -m 0700 /var/lib/agentic-platform
cd /opt/agentic-ps-platform
sudo -u agentic env PLATFORM_CA_KEY_PATH=/var/lib/agentic-platform/sandbox-ca node dist/ca-init.js | tee ~/ca-init.out
```

- Файл создаётся с правами 0600, существующий не перезаписывается (`EEXIST`). Каталог — постоянный том VPS: при потере файла УЦ меняется, и все выданные сертификаты агентов перестают действовать.
- В выводе — отпечаток SHA-256 корневого сертификата и сам корень в PEM. Закрытого ключа там нет. **Сохраните оба на Mac:**
  ```
  scp owner@<vps>:ca-init.out ~/sandbox/
  sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' ~/sandbox/ca-init.out > ~/sandbox/ca-root.crt
  grep 'отпечаток SHA-256' ~/sandbox/ca-init.out      # 64 hex — для --fingerprint
  ```
- Тот же корень и отпечаток позже передаются участникам песочницы: агентам, банкам, эквайреру (STATUS «За владельцем»).

## 5. Переменные: `/etc/agentic-platform/env`

```
sudo install -d -m 0755 /etc/agentic-platform
sudo install -m 0640 -o root -g agentic /dev/null /etc/agentic-platform/env
sudo nano /etc/agentic-platform/env
```

```
PLATFORM_ENV=sandbox
HOST=0.0.0.0
PORT=8443
PLATFORM_TLS_HOSTNAMES=<публичный IP>,<DNS-имя, если есть>
DATABASE_URL=postgres://agentic_platform:<пароль из шага 2>@127.0.0.1:5432/agentic_platform
PARTICIPANT_KEYS_PATH=/etc/agentic-platform/participants.json
PLATFORM_CA_KEY_PATH=/var/lib/agentic-platform/sandbox-ca
PAO_TRUSTED_PROXIES=
```

- **Все переменные — только здесь, не в строках `Environment=` unit.** Программа допуска читает именно этот файл. Если переменная задана в unit, сервис и приёмка увидят разное окружение.
- Пути — абсолютные. Относительный `PARAMS_PATH` программа допуска считала бы от другого каталога; без `PARAMS_PATH` используются стендовые параметры установки.
- Формат файла — простой `KEY=VALUE`. Комментарии `#` и кавычки вокруг значения допустимы, экранирование systemd (`\`, `$`) — нет.
- `PLATFORM_TLS_HOSTNAMES` — имена и адреса сертификата сервера. В `--host` приёмки указывайте одно из них. Пример: `PLATFORM_TLS_HOSTNAMES=sandbox.agentic-comm.ru,<публичный IP>`.
- `PARTICIPANT_KEYS_PATH` — доверенные ключи банков и эквайрера. Пока участников нет — пустой список:
  ```
  echo '{"participants": []}' | sudo tee /etc/agentic-platform/participants.json && sudo chmod 0644 /etc/agentic-platform/participants.json
  ```
- `PAO_TRUSTED_PROXIES` — пустой (раздел 0).

## 6. Unit systemd

`/etc/systemd/system/agentic-platform.service`:

```
[Unit]
Description=agentic-ps-platform sandbox
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=agentic
Group=agentic
WorkingDirectory=/opt/agentic-ps-platform
EnvironmentFile=/etc/agentic-platform/env
ExecStart=/usr/bin/node dist/main.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload && sudo systemctl enable --now agentic-platform
```

## 7. Перезапуск и журнал запуска

- Перезапуск: `sudo systemctl restart agentic-platform`. Сертификат сервера выпускается заново при каждом запуске, ключ хранится только в памяти. Срок сертификата — `agent_cert_ttl_days` (90 дней) от запуска; продления без перезапуска нет, планируйте перезапуск заранее.
- Журнал текущего запуска:
  ```
  journalctl -u agentic-platform -o cat --no-pager -n 50
  journalctl -u agentic-platform -o cat | grep 'УЦ песочницы загружен'
  ```
  В строке «УЦ песочницы загружен»: `ca_fingerprint` (должен совпасть с отпечатком из `ca:init`), `ca_not_after`, `tls_hostnames`, `server_cert_not_after`.
- Отказ запуска — строка самопроверки с кодом `STARTUP_*` до начала приёма соединений. Например: `STARTUP_CA_KEY_INVALID` — файл УЦ (с видом причины), `STARTUP_PROXIES_INVALID` — `PAO_TRUSTED_PROXIES`, `STARTUP_DB_REQUIRED` — нет `DATABASE_URL`, `STARTUP_PARAMS_INVALID` — `PORT`, `PLATFORM_TLS_HOSTNAMES` или параметры.
- Быстрая проверка с Mac: `curl --cacert ~/sandbox/ca-root.crt https://<имя>:8443/health` — ответ 200.

## 8. Доступ для приёмки (отдельный шаг)

Приёмка ходит на VPS по ssh под вашим пользователем `owner`, по ключу и без пароля (`BatchMode`). Её действия:

- создаёт временный каталог от имени `agentic` и копирует туда `operator.mjs`;
- запускает его на `node` поверх `dist` установки: допуск тестового агента и отзыв его сертификата;
- в конце удаляет каталог;
- читает журнал текущего запуска по `InvocationID`;
- перезапускает сервис (проверка 13).

Общего sudo не нужно, только эти команды.

`sudo visudo -f /etc/sudoers.d/agentic-acceptance` (замените `owner` на своего пользователя):

```
owner ALL=(agentic) NOPASSWD: /usr/bin/mktemp -d, /usr/bin/sh -c cat > /tmp/tmp.*/operator.mjs, /usr/bin/node /tmp/tmp.*/operator.mjs /opt/agentic-ps-platform /etc/agentic-platform/env, /usr/bin/rm -rf /tmp/tmp.*
owner ALL=(root) NOPASSWD: /usr/bin/systemctl restart agentic-platform
```

Право читать журнал службы — группа `systemd-journal` (после этого перезайдите по ssh):

```
sudo usermod -aG systemd-journal owner
```

- Без группы `journalctl` не падает, а выдаёт пустой вывод. Тогда проверки 12 и 13.12 покажут «строки „УЦ песочницы загружен“ нет», хотя на деле прав нет.
- Правило `rm -rf /tmp/tmp.*` и запуск `node` действуют от имени `agentic`, не root. `*` в sudoers совпадает и с пробелами, поэтому граница здесь — права пользователя `agentic`: ключ УЦ и EnvironmentFile ему и так доступны.

**Проверка шага — одна команда с Mac до приёмки** (ответ `ГОТОВО`; любой другой вывод — шаг не завершён):

```
ssh -o BatchMode=yes owner@<vps> 'd=$(sudo -n -u agentic /usr/bin/mktemp -d) && sudo -n -l -u agentic /usr/bin/node "$d/operator.mjs" /opt/agentic-ps-platform /etc/agentic-platform/env >/dev/null && sudo -n -u agentic /usr/bin/rm -rf "$d" && sudo -n -l /usr/bin/systemctl restart agentic-platform >/dev/null && id -nG | grep -qw systemd-journal && journalctl -u agentic-platform -o cat --no-pager | grep -q "УЦ песочницы загружен" && echo ГОТОВО'
```

## 9. Приёмка с Mac

Нужен Node ≥ 20.19 и копия репозитория: ветка `task/SANDBOX-ACC` до слияния PR #82, затем `main`.

```
cd ~/repos/agentic-ps-platform && npm ci
npm run acceptance -- --host <имя из PLATFORM_TLS_HOSTNAMES> --port 8443 \
  --ca ~/sandbox/ca-root.crt --fingerprint <64 hex из ca:init> --ssh owner@<vps>
```

Пример для `sandbox.agentic-comm.ru`:

```
npm run acceptance -- --host sandbox.agentic-comm.ru --port 8443 \
  --ca ~/sandbox/ca-root.crt --fingerprint <64 hex из ca:init> --ssh owner@sandbox.agentic-comm.ru
```

- Вывод — таблица «№ | Проверка | Ожидание | Факт | Пройдена» по 16 строкам (проверки 1–13 и повторы 13.1, 13.5, 13.12 после перезапуска) и итог «принято» или «не принято».
- Код выхода: 0 — принято, 1 — не принято, 2 — ошибка параметров.
- Принято — только если есть весь набор и все проверки пройдены. Любой сбой шага считается «не пройдена», а не пропуском.
- Проверка 13 перезапускает сервис: на несколько секунд песочница недоступна.
- Ключ подписи тестового агента и ключ его сертификата существуют только в памяти процесса приёмки на Mac. Платформе уходят открытый ключ и CSR. Ключ УЦ не покидает VPS.

| № | Проверка | Ожидание |
|---|---|---|
| 1 | Сертификат сервера | TLSv1.3, проверен по корню и имени, отпечаток корня = ожидаемому |
| 2 | TLS 1.2 | отказ по версии протокола (обрыв сети или таймаут не засчитываются) |
| 3 | Сохранённая сессия | полное рукопожатие |
| 4 | `http://` на порт сервиса | отказ |
| 5 | `/health`, `/.well-known/pao-configuration`, `/.well-known/agent-keys` без сертификата | 200 |
| 6 | `/pao/v1/agent`, подпись допущенного агента, без сертификата | 401 `AGENT_UNKNOWN` |
| 7 | Допуск с CSR → `/pao/v1/agent` с его сертификатом | 200, свой `agent_code` |
| 8 | Допуск без CSR | `APPLICATION_INCOMPLETE` |
| 9 | Сертификат чужого УЦ | 401 `AGENT_UNKNOWN` |
| 10 | Отзыв сертификата | 401 `AGENT_UNKNOWN` |
| 11 | Маршрут банка без подписи | 401 `SIGNATURE_INVALID` |
| 12 | Журнал запуска | `ca_fingerprint` = ожидаемому, `server_cert_not_after` = сроку сертификата из проверки 1 |
| 13 | Перезапуск, затем повтор 1, 5, 12 | сертификат сервера новый, остальное как до перезапуска |

## 10. Нюансы и остаточные риски

1. **Тестовые агенты остаются в реестре.** Каждый прогон допускает двух агентов `nspk:agent:acc-…:v1` (оператор `op-acceptance`, контур `sandbox`): с CSR и без (второму в допуске отказано, записи нет). Допущенный агент остаётся ACTIVE с отозванным сертификатом. Удаления из реестра нет, и без действующего сертификата ступень 0 его не пропустит. Если сбой случится между допуском и отзывом, сертификат останется действующим. Закрытый ключ к нему жил только в памяти процесса приёмки и уже потерян, так что воспользоваться сертификатом нельзя.
2. **Окружение программы допуска = EnvironmentFile.** Программа отказывает вне `PLATFORM_ENV=sandbox` (`ENV_NOT_SANDBOX`). С неверным `--env-file`, где тоже `sandbox`, допуск уйдёт в ту базу и тот УЦ, которые указаны в этом файле. Поэтому переменные — только в одном файле (раздел 5), и указывайте именно его.
3. **Билет сессии TLS 1.3.** Сервер с `SSL_OP_NO_TICKET` в TLS 1.3 всё же выдаёт билет: OpenSSL переключается на билеты с хранением состояния на сервере. Возобновления нет, потому что у сервера Node нет кэша сессий. В факте проверки 3 поэтому обычно «билет выдан, но полное рукопожатие». Сервер, который возобновляет сессии, проверка ловит (контрольный тест). Правка комментария в `server.ts` — хвосты SEC-1-код (сессия 56).
4. **Только порт сервиса.** Проверка 4 не видит HTTP на других портах; сверка — `ss -ltnp` (раздел 1).
5. **Отзыв проверяется на новом соединении.** Распространение отзыва на открытое keep-alive соединение в пределах `revocation_propagation_max_ms` приёмка не проверяет (STATUS «Открыто»).
6. **Исключение вне проверки** (например, при генерации ключей) завершает приёмку кодом 1 без таблицы. Это безопасно, но без отчёта (STATUS «Открыто»). По Ctrl+C временный каталог на VPS может остаться; в нём только `operator.mjs`, секретов нет. Удалить: `sudo -u agentic rm -rf /tmp/tmp.*`.
