# Песочница на VPS: установка и приёмка

Инструкция для развёртывания песочницы Платформы v0.40.0 на своём VPS и приёмки с Mac владельца командой `npm run acceptance` (SANDBOX-ACC, решение владельца от 28.10.2026). Основания: РП65 (сертификат агента по CSR), РП66 (TLS 1.3 в процессе, ступень 0, ключ УЦ из файла), РП67 (`PAO_TRUSTED_PROXIES` пустой), РП42 п. 4 (журнал запуска).

Команды §1–§9 с тегом v0.40.0 прогнаны на локальной ВМ Ubuntu 24.04.3 (UTM на Mac, сессия 71, 04–05.11.2026): приёмка — «принято, 16 из 16». Что на локальной ВМ не отрепетировано — раздел 11.

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

- Ubuntu 24.04 LTS — инструкция написана под неё. Пути sudoers (`/usr/bin/node`, `/usr/bin/sh`, `/usr/bin/mktemp`, `/usr/bin/rm`) и `secure_path` проверены на локальной ВМ (раздел 11); на ВМ Yandex Cloud команды ещё не запускались. Публичный IP; DNS-имя — по желанию.
- **Yandex Cloud** (схема создания ВМ, решение владельца 29.10):
  - группа безопасности ВМ: входящие — только 22/tcp и 8443/tcp; исходящие — любые (нужны для `npm ci` и обновлений). `ufw` ниже — второй слой, группа безопасности его не заменяет;
  - статический IP — в той же зоне доступности, что ВМ (адрес зональный);
  - ВМ не прерываемая: прерываемую облако останавливает, и песочница пропадает;
  - гарантированная доля vCPU — 100 % (2 vCPU, 4 ГБ). При меньшей доле приёмка ловит ложные тайм-ауты;
  - образ Ubuntu 24.04 LTS, вход по SSH-ключу (не OS Login), логин — не root.
- Сначала — обновление пакетов. `-y` не снимает вопросы пакетов (например, `keyboard-configuration`), поэтому нужен `DEBIAN_FRONTEND=noninteractive`. Если обновилось ядро, перезагрузите ВМ (`sudo reboot`):
  ```
  sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
  ```
  Сбой `fwupd.service` в выводе на ВМ без прошивок безвреден. apt и NodeSource (ниже) качают из сети: при тайм-аутах сначала смотрите зеркало (на локальной ВМ автоматически выбранное зеркало не отвечало — раздел 11).
- Открыты только порты 22 (ssh) и 8443 (Платформа):
  ```
  sudo ufw allow 22/tcp && sudo ufw allow 8443/tcp && sudo ufw enable
  ```
- Никакого HTTP на других портах (80, nginx и т. п.): приёмка проверяет только порт сервиса (проверка 4). Открытый HTTP где-то ещё она не увидит, поэтому сверьте вручную, что наружу слушаются только `:22` и `:8443`:
  ```
  sudo ss -ltnp
  ```
  Строки `127.0.0.53:53` и `127.0.0.54:53` (systemd-resolved) и `127.0.0.1:5432` (PostgreSQL, раздел 2) — только локальные, это норма. `ufw enable` спрашивает `Proceed with operation (y|n)?` — ответ `y`; правило для 22 добавлено раньше, ssh не обрывается.
- Node.js 22 из NodeSource, чтобы `node` лежал в `/usr/bin/node`. Этот путь входит в `secure_path` sudo, от него зависит программа приёмки.
  ```
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs git
  node -v   # v22.x, не ниже 20.19
  command -v node; sudo node -v   # /usr/bin/node; та же версия через secure_path
  ```

## 2. База PostgreSQL 16 со своим паролем

```
sudo apt-get install -y postgresql-16
PGPASS=$(openssl rand -hex 24)
sudo -u postgres psql -c "CREATE ROLE agentic_platform LOGIN PASSWORD '$PGPASS';"
sudo -u postgres psql -c "CREATE DATABASE agentic_platform OWNER agentic_platform;"
echo "$PGPASS"   # сохраните в менеджер паролей; дальше — только в EnvironmentFile
sudo ss -ltnp | grep 5432   # только 127.0.0.1:5432
psql -P pager=off "postgres://agentic_platform:$PGPASS@127.0.0.1:5432/agentic_platform" -c 'select version();'
```

- `PGPASS` живёт только в текущей ssh-сессии. EnvironmentFile (раздел 5) удобнее записать в той же сессии; в новой — задайте `PGPASS` из менеджера паролей.
- `-P pager=off`: иначе `psql` откроет результат в `less` (`(END)`), и это похоже на зависание.
- База слушает только `127.0.0.1`, как в PostgreSQL по умолчанию; наружу её не открывать.
- Пароль генерируется в hex, чтобы в `DATABASE_URL` не понадобилось экранирование.
- Миграции применяет сам процесс при запуске (самопроверка `db.migrations`).

## 3. Пользователь сервиса и v0.40.0

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin agentic
sudo git clone --branch v0.40.0 --depth 1 https://github.com/kuzin4u/agentic-ps-platform.git /opt/agentic-ps-platform
sudo git -C /opt/agentic-ps-platform log --oneline -1   # коммит тега v0.40.0
cd /opt/agentic-ps-platform && sudo npm ci
ls -l dist/main.js dist/ca-init.js
```

- Подсказка git про `detached HEAD` — норма для клона по тегу. Каталог принадлежит root, поэтому `git` в нём — через `sudo` (иначе `dubious ownership`).
- `npm ci` ставит зависимости ровно по lock-файлу и собирает `dist` (шаг `prepare`). Ядро `@kuzin4u/agentic-core` берётся по `git+https`. Ставятся и dev-зависимости: сборке нужен `tsc`, поэтому `--omit=dev` не годится. На локальной ВМ — около 1,5 мин; `npm warn deprecated` и итог `npm audit` запуск не останавливают, `npm audit fix` не запускать.
- Код принадлежит root, сервис его только читает.
- Установку для приёмки не меняйте: программа допуска приходит по ssh во временный каталог и удаляется после работы (раздел 8).

## 4. Ключ УЦ: `ca:init` (один раз)

```
sudo install -d -o agentic -g agentic -m 0700 /var/lib/agentic-platform
cd /opt/agentic-ps-platform
sudo -u agentic env PLATFORM_CA_KEY_PATH=/var/lib/agentic-platform/sandbox-ca node dist/ca-init.js | tee ~/ca-init.out
```

- Файл создаётся с правами 0600, существующий не перезаписывается (`EEXIST`). Каталог — постоянный том VPS: при потере файла УЦ меняется, и все выданные сертификаты агентов перестают действовать.
- **Повторно `ca:init` не запускать.** Повтор ответит `EEXIST`, но `| tee ~/ca-init.out` при этом затрёт сохранённый вывод первого запуска. Ключ из-за этого не пересоздавать: корень и отпечаток восстанавливаются из самого файла УЦ (в нём ключ и корень одним PEM); команда выводит только сертификат, ключ — нет:
  ```
  sudo -u agentic sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' /var/lib/agentic-platform/sandbox-ca > ~/ca-root.crt
  openssl x509 -in ~/ca-root.crt -noout -subject -fingerprint -sha256   # тот же отпечаток, с двоеточиями
  ```
  Отпечаток также есть в журнале каждого запуска (`ca_fingerprint`, раздел 7).
- В выводе — отпечаток SHA-256 корневого сертификата и сам корень в PEM. Закрытого ключа там нет. **Сохраните оба на Mac:**
  ```
  mkdir -p ~/sandbox && chmod 0700 ~/sandbox
  scp owner@<vps>:ca-init.out ~/sandbox/
  sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' ~/sandbox/ca-init.out > ~/sandbox/ca-root.crt
  grep 'отпечаток SHA-256' ~/sandbox/ca-init.out      # 64 hex — для --fingerprint
  openssl x509 -in ~/sandbox/ca-root.crt -noout -subject -enddate -fingerprint -sha256   # тот же отпечаток, с двоеточиями и в верхнем регистре
  ```
- Тот же корень и отпечаток позже передаются участникам песочницы: агентам, банкам, эквайреру (STATUS «За владельцем»).

## 5. Переменные: `/etc/agentic-platform/env`

```
sudo install -d -m 0755 /etc/agentic-platform
sudo install -m 0640 -o root -g agentic /dev/null /etc/agentic-platform/env
```

Файл пишется командой, не редактором: в nano легко вставить лишнюю строку. Пароль берётся из `$PGPASS` раздела 2 и на экран не выводится; `<публичный IP>` и DNS-имя подставьте до запуска:

```
sudo tee /etc/agentic-platform/env >/dev/null <<EOF
PLATFORM_ENV=sandbox
HOST=0.0.0.0
PORT=8443
PLATFORM_TLS_HOSTNAMES=<публичный IP>,<DNS-имя, если есть>
DATABASE_URL=postgres://agentic_platform:${PGPASS}@127.0.0.1:5432/agentic_platform
PARTICIPANT_KEYS_PATH=/etc/agentic-platform/participants.json
PLATFORM_CA_KEY_PATH=/var/lib/agentic-platform/sandbox-ca
PAO_TRUSTED_PROXIES=
EOF
sudo grep -c '^DATABASE_URL=postgres://agentic_platform:[0-9a-f]\{48\}@127.0.0.1' /etc/agentic-platform/env   # 1 — пароль подставлен
sudo grep -c '^[A-Z_]*=' /etc/agentic-platform/env   # 8
sudo grep -v '^DATABASE_URL=' /etc/agentic-platform/env
sudo stat -c '%a %U:%G' /etc/agentic-platform/env   # 640 root:agentic
```

- **Все переменные — только здесь, не в строках `Environment=` unit.** Программа допуска читает именно этот файл. Если переменная задана в unit, сервис и приёмка увидят разное окружение.
- Пути — абсолютные. Относительный `PARAMS_PATH` программа допуска считала бы от другого каталога; без `PARAMS_PATH` используются стендовые параметры установки.
- Формат файла — простой `KEY=VALUE`. Комментарии `#` и кавычки вокруг значения допустимы, экранирование systemd (`\`, `$`) — нет.
- `PLATFORM_TLS_HOSTNAMES` — имена и адреса сертификата сервера. В `--host` приёмки указывайте одно из них. Пример: `PLATFORM_TLS_HOSTNAMES=sandbox.agentic-comm.ru,<публичный IP>`.
- `PARTICIPANT_KEYS_PATH` — доверенные ключи банков и эквайрера. Пока участников нет — пустой список:
  ```
  echo '{"participants": []}' | sudo tee /etc/agentic-platform/participants.json && sudo chmod 0644 /etc/agentic-platform/participants.json
  ```
  Тестовый банк-участник — раздел 9а: запись из `npm run participant -- keygen`, затем перезапуск.
- `PAO_TRUSTED_PROXIES` — пустой (раздел 0).

## 6. Unit systemd

`/etc/systemd/system/agentic-platform.service` — тоже командой:

```
sudo tee /etc/systemd/system/agentic-platform.service >/dev/null <<'EOF'
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
EOF
sudo systemd-analyze verify /etc/systemd/system/agentic-platform.service; echo "verify=$?"   # 0
```

```
sudo systemctl daemon-reload && sudo systemctl enable --now agentic-platform
systemctl is-active agentic-platform; sudo ss -ltnp | grep 8443   # active; 0.0.0.0:8443 у node
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
- Быстрая проверка с Mac: `curl --cacert ~/sandbox/ca-root.crt https://<имя>:8443/health` — ответ 200 (`{"status":"ok","env":"sandbox",…}`). Системный `curl` macOS 12 (8.7.1, SecureTransport) TLS 1.3 держит — проверено на локальной ВМ.

## 8. Доступ для приёмки (отдельный шаг)

Приёмка ходит на VPS по ssh под вашим пользователем `owner`, по ключу и без пароля (`BatchMode`). Её действия:

- создаёт временный каталог от имени `agentic` и копирует туда `operator.mjs`;
- запускает его на `node` поверх `dist` установки: допуск тестового агента и отзыв его сертификата;
- в конце удаляет каталог;
- читает журнал текущего запуска по `InvocationID`;
- перезапускает сервис (проверка 13).

Общего sudo не нужно, только эти команды.

Файл `/etc/sudoers.d/agentic-acceptance` (замените `owner` на своего пользователя). Ошибка в файле внутри `sudoers.d` ломает весь `sudo`, поэтому — через временный файл и проверку `visudo`:

```
sudo tee /tmp/agentic-acceptance >/dev/null <<'EOF'
owner ALL=(agentic) NOPASSWD: /usr/bin/mktemp -d, /usr/bin/sh -c cat > /tmp/tmp.*/operator.mjs, /usr/bin/node /tmp/tmp.*/operator.mjs /opt/agentic-ps-platform /etc/agentic-platform/env, /usr/bin/rm -rf /tmp/tmp.*
owner ALL=(root) NOPASSWD: /usr/bin/systemctl restart agentic-platform
EOF
sudo visudo -cf /tmp/agentic-acceptance && sudo install -m 0440 -o root -g root /tmp/agentic-acceptance /etc/sudoers.d/agentic-acceptance && sudo rm /tmp/agentic-acceptance && sudo visudo -c
```

Приёмка вызывает программы без пути (`sudo -n -u agentic mktemp -d`, `sh -c "cat > …"`, `node`, `rm`); `sudo` находит их через `secure_path` в `/usr/bin` и сверяет с правилами — на локальной ВМ без запроса пароля.

**Правила — только на время приёмки** (решение владельца 05.11, PR #104): они по сути дают оболочку от `agentic`, а у него есть доступ к ключу УЦ (STATUS «Открыто»). Сразу после приёмки — `sudo rm /etc/sudoers.d/agentic-acceptance && sudo visudo -c`; перед следующей приёмкой — поставить заново командами выше (через временный файл и `visudo -cf`) и повторить проверку шага.

Право читать журнал службы — группа `systemd-journal` (после этого перезайдите по ssh):

```
sudo usermod -aG systemd-journal owner
```

- Без группы `journalctl` не падает, а выдаёт пустой вывод. Тогда проверки 12 и 13.12 покажут «строки „УЦ песочницы загружен“ нет», хотя на деле прав нет. Исключение — группа `adm`: первый пользователь, созданный установщиком Ubuntu, в ней состоит и журнал читает и без `systemd-journal`. Пользователь ВМ Yandex Cloud получает те группы, что заданы при создании ВМ. Проверка шага ниже требует именно `systemd-journal`, поэтому `usermod` выполняйте в любом случае.
- Правило `rm -rf /tmp/tmp.*` и запуск `node` действуют от имени `agentic`, не root. `*` в sudoers совпадает и с пробелами, поэтому граница здесь — права пользователя `agentic`: ключ УЦ и EnvironmentFile ему и так доступны.

**Проверка шага — одна команда с Mac до приёмки** (ответ `ГОТОВО`; любой другой вывод — шаг не завершён):

```
ssh -o BatchMode=yes owner@<vps> 'd=$(sudo -n -u agentic /usr/bin/mktemp -d) && sudo -n -l -u agentic /usr/bin/node "$d/operator.mjs" /opt/agentic-ps-platform /etc/agentic-platform/env >/dev/null && sudo -n -u agentic /usr/bin/rm -rf "$d" && sudo -n -l /usr/bin/systemctl restart agentic-platform >/dev/null && id -nG | grep -qw systemd-journal && journalctl -u agentic-platform -o cat --no-pager | grep -q "УЦ песочницы загружен" && echo ГОТОВО'
```

## 9. Приёмка с Mac

Приёмка запускается **с Mac**, не на VPS. Нужен Node ≥ 20.19 и копия репозитория на теге той же версии, что установлена на VPS (`git checkout v0.40.0`). Подойдёт и другая ветка, если код приёмки и Платформы в ней тот же: `git diff --stat v0.40.0 -- scripts src config package.json package-lock.json` пуст.

Перед приёмкой проверьте нагрузку Mac (`uptime`): при 10 и выше закройте тяжёлые процессы, иначе ложные тайм-ауты не отличить от настоящих.

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

## 9а. Тестовый банк-участник с Mac

Подпись и отзыв мандата клиентом в песочнице делает только банк-участник по ПИ-8. Рабочий сервер ключа эмулятора эмитента не принимает. Тестовый банк — инструмент `npm run participant` на Mac (Р-1031, Р-1040). Сервер для этого не меняется: ПИ-8 уже на том же порту, по HTTPS, без клиентского сертификата. Банку доверяют по подписи тела его ключом из `participants.json`.

Нужен Node ≥ 20.19 и копия репозитория (`npm ci`), как для приёмки. `--silent` убирает строку-заголовок npm из вывода.

**1. Ключ банка — один раз, вне клона репозитория:**

```
mkdir -p ~/sandbox && chmod 0700 ~/sandbox
cd ~/repos/agentic-ps-platform
npm run --silent participant -- keygen --code test-bank --key ~/sandbox/test-bank.pem > ~/sandbox/test-bank.json
```

- Закрытый ключ — PKCS8 PEM с правами 0600. Существующий файл не перезаписывается (`KEY_EXISTS`). Путь внутри клона отклоняется (`KEY_PATH_IN_REPO`; сверка с корнем git по реальным путям). Каталог должен существовать.
- Вывод — только открытая запись: `participant_code`, `kid`, `alg`, `public_key`, `revocation_order` (`bank:test-bank:revocation:v1`). Запись проверена тем же конструктором, что и в рабочем сервере. Код эмулятора стенда (`stand:…`) или недопустимый код — `CODE_INVALID`, ключ не пишется.
- Ключ не покидает Mac. На VPS уходит только запись.

**2. Запись в `participants.json` и перезапуск:**

```
node -e 'const r=JSON.parse(require("fs").readFileSync(0,"utf8"));console.log(JSON.stringify({participants:[r]},null,2))' \
  < ~/sandbox/test-bank.json > ~/sandbox/participants.json
scp ~/sandbox/participants.json owner@<vps>:/tmp/participants.json
ssh -t owner@<vps> 'sudo install -m 0644 -o root -g root /tmp/participants.json /etc/agentic-platform/participants.json && rm /tmp/participants.json && sudo systemctl restart agentic-platform'
```

- Список читается только при запуске, поэтому после правки нужен перезапуск.
- Ошибка в файле — отказ запуска `STARTUP_PARTICIPANTS_INVALID` (раздел 7). Боевой банк-участник в песочнице допустим только один (`MAX_LIVE_PARTICIPANTS = 1`): второй банк тоже даст отказ запуска.

**3. Подпись мандата.** `id` и `hash` мандата — из ответа агента на `GET /pao/v1/mandates/{id}`. Мандат должен быть в `PENDING_SIGNATURE`. Метода, через который банк сам прочитал бы мандат, в ПИ-8 нет (раздел 10 п. 8).

```
npm run --silent participant -- sign --host sandbox.agentic-comm.ru --port 8443 \
  --ca ~/sandbox/ca-root.crt --fingerprint <64 hex из ca:init> \
  --key ~/sandbox/test-bank.pem --code test-bank \
  --mandate <id> --hash <hash> [--decision SIGN|REJECT] [--signature-type simple|qualified|gov_id] [--token-consent]
```

- По умолчанию: `--decision SIGN`, `--signature-type simple`, `token_consent` — `false`. Без `--token-consent` клиент не дал согласия на токен.
- Ответ: `{"status": 200, "body": {"mandate_id": "…", "status": "ACTIVE"}}` (при `REJECT` — `REJECTED`).

**4. Отзыв мандата клиентом:**

```
npm run --silent participant -- revoke --host sandbox.agentic-comm.ru --port 8443 \
  --ca ~/sandbox/ca-root.crt --fingerprint <64 hex из ca:init> \
  --key ~/sandbox/test-bank.pem --code test-bank --mandate <id> --hash <hash>
```

Ответ — `REVOKED`. Повтор по уже отозванному мандату — текущий статус без новой записи.

**Коды выхода и отказы:**
- Коды выхода: 0 — ПИ-8 ответил 200; 1 — отказ инструмента или ПИ-8; 2 — ошибка параметров.
- До соединения: `FINGERPRINT_MISMATCH` (отпечаток файла `--ca` ≠ `--fingerprint`), `CA_INVALID`, `KEY_INVALID`, `ARGS_INVALID` (`--hash` — 64 hex в нижнем регистре).
- Рукопожатие: доверие только корню из `--ca`, имя сервера проверяется по сертификату. `CONNECT_FAILED` — с кодом Node, например `ERR_TLS_CERT_ALTNAME_INVALID`, если `--host` нет в `PLATFORM_TLS_HOSTNAMES`.
- Ответы ПИ-8 (`body.code`):

| HTTP | `code` | Причина |
|---|---|---|
| 401 | `SIGNATURE_INVALID` | ключа нет в `participants.json`, не тот `--code`, или CART, корневой INTENT которого подписал не этот банк |
| 404 | `MANDATE_NOT_FOUND` | неверный `--mandate` |
| 409 | `MANDATE_HASH_MISMATCH` | `--hash` ≠ `Mandate.hash` |
| 409 | `MANDATE_NOT_PENDING` | решение уже принято другой подписью |
| 422 | `QUALIFIED_SIGNATURE_REQUIRED` | выше порога простой подписи (`--signature-type qualified`) |

## 10. Нюансы и остаточные риски

1. **Тестовые агенты остаются в реестре.** Каждый прогон допускает двух агентов `nspk:agent:acc-…:v1` (оператор `op-acceptance`, контур `sandbox`): с CSR и без (второму в допуске отказано, записи нет). Допущенный агент остаётся ACTIVE с отозванным сертификатом. Удаления из реестра нет, и без действующего сертификата ступень 0 его не пропустит. Если сбой случится между допуском и отзывом, сертификат останется действующим. Закрытый ключ к нему жил только в памяти процесса приёмки и уже потерян, так что воспользоваться сертификатом нельзя.
2. **Окружение программы допуска = EnvironmentFile.** Программа отказывает вне `PLATFORM_ENV=sandbox` (`ENV_NOT_SANDBOX`). С неверным `--env-file`, где тоже `sandbox`, допуск уйдёт в ту базу и тот УЦ, которые указаны в этом файле. Поэтому переменные — только в одном файле (раздел 5), и указывайте именно его.
3. **Билет сессии TLS 1.3.** Сервер с `SSL_OP_NO_TICKET` в TLS 1.3 всё же выдаёт билет: OpenSSL переключается на билеты с хранением состояния на сервере. Возобновления нет, потому что у сервера Node нет кэша сессий. В факте проверки 3 поэтому обычно «билет выдан, но полное рукопожатие». Сервер, который возобновляет сессии, проверка ловит (контрольный тест). Правка комментария в `server.ts` — хвосты SEC-1-код (сессия 56).
4. **Только порт сервиса.** Проверка 4 не видит HTTP на других портах; сверка — `ss -ltnp` (раздел 1).
5. **Отзыв проверяется на новом соединении.** Распространение отзыва на открытое keep-alive соединение в пределах `revocation_propagation_max_ms` приёмка не проверяет (STATUS «Открыто»).
6. **Исключение вне проверки** (например, при генерации ключей) завершает приёмку кодом 1 без таблицы. Это безопасно, но без отчёта (STATUS «Открыто»). По Ctrl+C временный каталог на VPS может остаться; в нём только `operator.mjs`, секретов нет. Удалить: `sudo -u agentic rm -rf /tmp/tmp.*`.
7. **Время решения и отзыва банка — по часам Mac.** `signed_at` и `revoked_at` ставит инструмент. Сервер с часами Платформы их не сверяет, поэтому в выписке время банка, а не Платформы. Пересмотр — перед пилотом с банком, вместе с п. 8 (STATUS «Открыто»).
8. **`--hash` — вручную от агента.** Банк подписывает `Mandate.hash` из ответа агента на `GET /pao/v1/mandates/{id}`, не видя содержания мандата: чтения мандата банком в ПИ-8 нет (STATUS «Открыто»). Чужой хэш сервер отклонит (`MANDATE_HASH_MISMATCH`), но что именно подписано, тестовый банк сам не проверяет.
9. **Сверка отпечатка — общая с приёмкой.** `normFingerprint` инструмент берёт из `scripts/acceptance/checks.ts`. Правка приёмки меняет и сверку у тестового банка; тест `tests/unit/participant-https.test.ts` это ловит.
10. **Ключ банка — файл на Mac.** Права 0600 инструмент ставит только при создании. Переносить ключ в клон репозитория, в облачную папку или на VPS нельзя. Потеря ключа — новый `keygen` в другой файл (новый `kid`), новая запись в `participants.json` и перезапуск.
11. **Параметры песочницы — стендовые.** Без `PARAMS_PATH` загружается `config/params.stand.json` установки (PARAMS.md, РП25). В нём стендовые имена: `event_subscription_allow_hosts` (`agent-emulator.stand`), `participant_notify_allow_hosts` (`issuer-emulator.stand`), `upk_page_base_url` (`https://upk.stand`). Push-подписка агента, вебхук банка и ссылки УПК в песочнице поэтому упираются в отказ (fail-closed); приёмку это не задевает (STATUS «Открыто»).

## 11. Репетиция на локальной ВМ

Сессия 71 (04–05.11.2026): ВМ Ubuntu 24.04.3 Server в UTM 5.0.6 на Mac с macOS 12 (Intel), 2 vCPU, 4 ГБ, 20 ГБ, сеть «Shared Network» (адрес 192.168.64.x доступен с Mac напрямую). Разделы 1–9 выполнены с тегом v0.40.0, приёмка — «принято, 16 из 16». Журнал прогона — комментарии PR #104.

**Не отрепетировано на локальной ВМ** — проверять при установке в Yandex Cloud:
- группа безопасности (входящие 22 и 8443) — на локальной ВМ только `ufw`;
- статический IP и его зона;
- DNS-имя: в `PLATFORM_TLS_HOSTNAMES` и `--host` был только адрес;
- гарантированная доля vCPU (100 %);
- смена адреса ВМ: сертификат сервера выпускается на имена из `PLATFORM_TLS_HOSTNAMES` при запуске. Новый адрес — правка EnvironmentFile и перезапуск, иначе `ERR_TLS_CERT_ALTNAME_INVALID`;
- `{"error":"SCHEMA_NOT_READY"}` у `operator.mjs` до первого старта сервиса (STATUS «Открыто»): на локальной ВМ сервис стартовал раньше.

**Особенности локальной ВМ** (к Yandex Cloud не относятся):
- UTM: режим «Virtualize» с бэкендом QEMU. С виртуализацией Apple на macOS 12 UTM загружает только образ ядра, не ISO. Multipass на macOS 12 не годится: 1.15 и новее требует macOS 13, а в 1.14 не исправлена уязвимость повышения прав;
- установщик Ubuntu: LVM включён по умолчанию (снять — иначе корню достаётся около половины диска), «Install OpenSSH server» выключен по умолчанию (включить); автоматически выбранное зеркало может не отвечать — «Restart the installer» и `http://archive.ubuntu.com/ubuntu/`;
- ISO не извлекается кнопкой CD/DVD работающей ВМ: выйти из UTM, затем Настройки → Диски → CD/DVD → «Очистить»;
- в консоли UTM нет общего буфера обмена — команды вводятся по ssh с Mac;
- вход по паролю после `ssh-copy-id` выключается файлом `/etc/ssh/sshd_config.d/00-no-password.conf` с `PasswordAuthentication no`: sshd берёт первое значение, а установщик пишет `yes` в `50-cloud-init.conf`.
