-- П1 Реестр агентов на PostgreSQL (РП64 п. 1–2, PS-05в ч. 2а): записи агентов, владельцы «сторона : идентификатор»,
-- ключи агентов и подписка на события. Строки агентов не удаляются: исключённый — EXCLUDED. Номера карты и сведений
-- о принципале нет (инвариант 1, A2 п. 1.2). Подключение к серверу — PS-05в ч. 2б.

-- Владелец «сторона : идентификатор» (A2 п. 4.1, РП21 п. 2): вставляется с первой версией агента; другая версия того же
-- идентификатора другим оператором — CODE_TAKEN по этой строке, две одновременные вставки разных операторов не пройдут обе.
CREATE TABLE agent_ids (
  issuer   text NOT NULL,
  id       text NOT NULL,
  operator text NOT NULL,
  PRIMARY KEY (issuer, id)
);

CREATE TABLE agents (
  agent_code          text PRIMARY KEY,
  -- Порядок допуска — для каталога ключей (РП22 п. 1).
  seq                 bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  issuer              text NOT NULL,
  id                  text NOT NULL,
  version             integer NOT NULL CHECK (version >= 1),
  operator            text NOT NULL,
  class               text NOT NULL CHECK (class IN ('BUYER', 'SELLER', 'SURFACE', 'SERVICE')),
  level               integer NOT NULL CHECK (level >= 1),
  status              text NOT NULL,
  status_ground       text NULL,
  model               text NOT NULL,
  runtime             text NOT NULL,
  contour             text NOT NULL CHECK (contour IN ('sandbox', 'operator')),
  conformance_run_ref text NULL,
  admitted_at         timestamptz NOT NULL,
  status_changed_at   timestamptz NOT NULL,
  -- Время последнего приостановления; при снятии сохраняется (РП54 п. 5–6).
  suspended_at        timestamptz NULL,
  -- Растёт только сменой статуса: по ней event_id события agent.* (РП54 п. 2).
  row_version         bigint NOT NULL CHECK (row_version >= 1),
  FOREIGN KEY (issuer, id) REFERENCES agent_ids (issuer, id),
  -- Основание — по статусу (РП21 п. 4): у ACTIVE нет, у SUSPENDED — A2 п. 7.1, у EXCLUDED — те же и WITHDRAWN.
  -- IS NOT NULL явно: NULL IN (…) — NULL, а CHECK с NULL не нарушен — SUSPENDED без основания прошёл бы.
  CONSTRAINT agents_status_ground CHECK (
    (status = 'ACTIVE' AND status_ground IS NULL)
    OR (status = 'SUSPENDED' AND status_ground IS NOT NULL
      AND status_ground IN ('KEY_COMPROMISE', 'OUT_OF_MANDATE', 'FALSE_INFORMATION', 'INCIDENT_EVASION'))
    OR (status = 'EXCLUDED' AND status_ground IS NOT NULL
      AND status_ground IN ('KEY_COMPROMISE', 'OUT_OF_MANDATE', 'FALSE_INFORMATION', 'INCIDENT_EVASION', 'WITHDRAWN'))
  )
);

-- kid занят глобально (KeyTakenError, РП23 п. 2–3); ключ ищется только среди ключей своего агента.
CREATE TABLE agent_keys (
  kid         text PRIMARY KEY,
  agent_code  text NOT NULL REFERENCES agents (agent_code),
  alg         text NOT NULL,
  public_key  text NOT NULL,
  valid_from  timestamptz NOT NULL,
  valid_to    timestamptz NOT NULL,
  -- Отзыв необратим (РП23 п. 5).
  revoked_at  timestamptz NULL,
  created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  row_version bigint NOT NULL CHECK (row_version >= 1)
);
CREATE INDEX agent_keys_agent ON agent_keys (agent_code);

-- Подписка в записи агента (РП40 п. 1): заменяется целиком; пустой events — push выключен.
CREATE TABLE agent_subscriptions (
  agent_code text PRIMARY KEY REFERENCES agents (agent_code),
  url        text NOT NULL,
  events     text[] NOT NULL
);
