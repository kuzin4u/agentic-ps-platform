# Журнал изменений

Изменения, заметные потребителям пакета: агенту (`agentic-buyer-ref`), ядру (`agentic-core`) и тем, кто подключает стенд
(`agentic-ps-platform/stand`) и фикстуры (`agentic-ps-platform/fixtures`). Версия пакета — `package.json`; тег `vX.Y.Z`
ставит владелец на коммит слияния в `main`. Версия ПАО — `info.version` в `docs/core/agent-protocol.yaml`, сверка копий —
по `PAO_SPEC_SHA256` (`src/shared/pao-errors.generated.ts`). Записи до v0.4.0 — в описаниях PR и тегах.

## v0.4.0 — 18.10.2026

PS-06 «Журнал согласий (П2)», PR #30. ПАО 1.4.0, `PAO_SPEC_SHA256` =
`48bd339746e83c0468fb8354d6b2d8f0c82020904af549063d3e44b1a51ad9da`. Решения РП33–РП38.

### Ломает для потребителей стенда

- **`PARTICIPANT_KEYS_PATH`: у участника обязателен `revocation_order`** (РП37). Запись участника без него или с разными
  значениями в записях ключей одного участника — ошибка при старте. Если порядок отзыва у участника не задан, запрос
  мандата получает 503 (РП37 п. 4).
- **`signature_ref` и `revocation_ref` в ПИ-8 — по маске без ПДн** (РП38 доп. п. 2): латиница, цифры, `_`, `-`, до 64
  знаков, без семи цифр подряд; иначе 400 `REQUEST_INVALID`. Ссылки уходят агенту в выписке.

### ПАО 1.4.0 (совместимо с 1.3.0, AGENT-PROTOCOL §7)

- `POST /pao/v1/mandates` (INTENT, CART под INTENT): id мандата вычисляется от агента и `Idempotency-Key`, повтор тем же
  ключом — тот же мандат в любой срок (РП33 доп.); ответы 401/403/404/409/503 объявлены (РП33, РП35).
- `GET /pao/v1/mandates/{id}`: чужой и неизвестный — одинаковый 404 `MANDATE_NOT_FOUND` (РП34).
- `Mandate.revocation_order` и `Mandate.agent_code` — обязательные поля ответа; порядок отзыва — от Платформы из записи
  участника, входит в `Mandate.hash` (РП37).
- `POST /pao/v1/mandates/{id}/relinquish` — отказ агента от полномочий (РП38 п. 3).
- `GET /pao/v1/mandates/{id}/verify` — ровно `{outcome, amount_left, valid_to, as_of}`, без предмета (РП38 п. 6).
- `GET /pao/v1/mandates/{id}/evidence` — выписка с `records`: цепочка и подписи банка проверяются без Платформы (РП38 п. 7).
- Статус CART при отзыве или истечении родителя — РП35; правило свёртки записей — в AGENT-PROTOCOL §3 (РП38 п. 5).
- Ответы и события Платформы в 1.4.0 по-прежнему не подписаны: подпись — ПАО 1.5.0 (РП26, РП37).

### ПИ-8 (шлюз участников)

- `POST /participants/v1/mandates/{id}/sign` — решение клиента (подпись или отказ) с подписью Ed25519 банка, метка
  `pao:participant-mandate-signature:v1` (РП36).
- `POST /participants/v1/mandates/{id}/revoke` — отзыв клиентом через банк, метка
  `pao:participant-mandate-revocation:v1` (РП38 п. 1).

### Стенд (`agentic-ps-platform/stand`)

- `issuer.sign(mandateId, opts?)` — эмулятор эмитента подписывает мандат и шлёт тот же запрос ПИ-8 `sign`.
- `issuer.revoke(mandateId)` — отзыв клиентом через эмулятор эмитента (ПИ-8 `revoke`).
- `issuer.trustedKey` — открытый ключ эмулятора: проверка подписей банка в выписке без Платформы.

### Пока нет

- Событий `mandate.signed` и `mandate.revoked` агенту — PS-08.
- Остатка бюджета в `verify`: до PS-09 — предел мандата.
