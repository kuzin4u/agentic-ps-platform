// Реестры кодов Платформы в формате /diag agentic-core (К17, РП42). Три реестра, не объединённых в один:
// у 11 из 13 кодов ПИ то же имя, что у кода ПАО, а получатель и действие другие (РП42 п. 2).
// Коды ПАО — PAO_DIAG ядра как есть, свой реестр ПАО не пишется. Полнота — tests/unit/diag-registry.test.ts (К1.4).
import type { DiagAction, DiagEntry, DiagSource } from "@kuzin4u/agentic-core/diag";
import { DECISION_REASON, PI_VERSION } from "./canonical.generated.js";

export { PAO_DIAG } from "@kuzin4u/agentic-core/pao";

type PiCode = (typeof DECISION_REASON)[number];

const T6 = "ПИ §6";

function pi(code: PiCode, source: DiagSource[], action: DiagAction, human: string, operator: string, norm: string): DiagEntry {
  return { code, component: "pi", source, action, human: { ru: human }, operator: { ru: operator }, norm, since: PI_VERSION };
}

/**
 * Коды причин отказа и подтверждения ПИ (ПИ §6), получатель — процессинг и эквайрер; человек видит отказ у продавца.
 * Номер кода ответа ОПКЦ — [альбом], в запись не входит (РП6).
 */
export const PI_DIAG: Readonly<Record<PiCode, DiagEntry>> = {
  AOI_MISSING: pi("AOI_MISSING", ["merchant"], "after_fix",
    "Покупка через помощника не прошла по технической причине на стороне магазина.",
    "Агентская операция без признака aoi или кода агента: эквайрер или продавец не передал признак. Сверить разметку сообщения.", `A1 п. 3.2; ${T6}`),
  AOI_MISMATCH: pi("AOI_MISMATCH", ["agent", "merchant"], "stop",
    "Покупка через помощника отклонена. Обратитесь в поддержку сервиса.",
    "Код агента в признаке не равен домену токена: подмена или ошибка разметки, источник неразличим. Инцидент, операцию не повторять.", `A1 п. 8.2; ${T6}`),
  AGENT_UNKNOWN: pi("AGENT_UNKNOWN", ["agent"], "stop",
    "Помощник не допущен к покупкам. Обратитесь в поддержку сервиса.",
    "Агента из признака или домена токена нет в реестре Платформы.", `A1 п. 5.3; РП21; ${T6}`),
  AGENT_SUSPENDED: pi("AGENT_SUSPENDED", ["platform"], "stop",
    "Помощник временно отключён от покупок. Обратитесь в поддержку сервиса.",
    "Допуск агента приостановлен оператором Платформы; агентские операции отклоняются до снятия.", `A1 п. 5.3; A2 п. 7.1; ${T6}`),
  CREDENTIAL_INVALID: pi("CREDENTIAL_INVALID", ["agent", "bank"], "after_fix",
    "Покупка не прошла по технической причине. Повторите позже.",
    "Криптограмма агентского реквизита неверна или уже использована: операция — только с новым реквизитом.", `A3 п. 4.4; ${T6}`),
  MANDATE_NOT_FOUND: pi("MANDATE_NOT_FOUND", ["agent", "platform"], "after_human",
    "Поручение на покупку не найдено. Оформите новое поручение.",
    "Мандата для реквизита операции нет или он другого агента (РП34).", `A7 п. 8.1–8.6; ${T6}`),
  MANDATE_EXPIRED: pi("MANDATE_EXPIRED", ["client"], "after_human",
    "Срок поручения на покупку истёк. Оформите новое поручение.",
    "Мандат операции в статусе EXPIRED (свой срок или срок родителя, РП35).", `A7 п. 2.1; ${T6}`),
  MANDATE_REVOKED: pi("MANDATE_REVOKED", ["client"], "stop",
    "Поручение на покупку отозвано или отклонено.",
    "Мандат операции в статусе REVOKED или REJECTED (отзыв клиентом, отказ банка, отзыв родителя).", `A7 п. 6; ${T6}`),
  MANDATE_SCOPE: pi("MANDATE_SCOPE", ["agent"], "after_human",
    "Покупка выходит за рамки поручения: другой продавец или категория.",
    "Продавец или категория операции вне предмета мандата (сопоставление с записью мандата, инвариант 5).", `A3 п. 4.1; ${T6}`),
  LIMIT_EXCEEDED: pi("LIMIT_EXCEEDED", ["agent", "client"], "after_human",
    "Покупка превышает сумму, разрешённую поручением.",
    "Сумма операции из сообщения процессинга больше остатка бюджета мандата или лимита клиента (РП11, РП41).", `A3 п. 5.1–5.3, п. 7.2; ${T6}`),
  STATE_UNAVAILABLE: pi("STATE_UNAVAILABLE", ["platform"], "retry_same_key",
    "Не удалось подтвердить покупку. Повторите позже.",
    "Бюджет или статус мандата не подтверждён (сбой П2 или П3): отказ, не догадка; повтор операции — по правилам процессинга.", `A3 п. 4.5; ${T6}`),
  CONFIRMATION_REQUIRED: pi("CONFIRMATION_REQUIRED", ["client"], "after_human",
    "Нужно ваше подтверждение покупки в приложении банка или на странице оплаты.",
    "Порог подтверждения: аналог мягкого отказа, операция — после подтверждения человеком (инвариант 7).", `A7 п. 7.2; ${T6}`),
  ADP_UNAVAILABLE: pi("ADP_UNAVAILABLE", ["platform", "environment"], "retry_same_key",
    "Не удалось проверить покупку через помощника. Повторите позже.",
    "Таймаут ADP: код ставит процессинг от своего имени (РП19); неагентские операции не затронуты (РП4).", `РП19; ${T6}`),
};

/** Коды П3 без пары в ПАО (РП41 п. 5): внутренние, на границе их сопоставляет вызывающий (РП42 п. 9). */
export const PLATFORM_STATE_CODES = ["RESERVATION_RELEASED", "COMMIT_CONFLICT"] as const;

/** Коды самопроверки при старте (РП42 п. 4); проверки — src/shared/selfcheck.ts (К1.5). */
export const STARTUP_CODES = [
  "STARTUP_PARAMS_INVALID",
  "STARTUP_PROXIES_INVALID",
  "STARTUP_DB_REQUIRED",
  "STARTUP_DB_MEMORY",
  "STARTUP_DB_MIGRATIONS",
  "STARTUP_PARTICIPANTS_INVALID",
  "STARTUP_PAO_SPEC_MISMATCH",
  "STARTUP_DIAG_INCOMPLETE",
] as const;

export const PLATFORM_DIAG_CODES = [...PLATFORM_STATE_CODES, ...STARTUP_CODES] as const;
type PlatformCode = (typeof PLATFORM_DIAG_CODES)[number];

/** Человек кодов самопроверки не видит: при fail Платформа не принимает трафик; текст — для того, кто покажет недоступность. */
const DOWN = "Сервис временно недоступен. Повторите позже.";

function platform(
  code: PlatformCode,
  source: DiagSource[],
  action: DiagAction,
  human: string,
  operator: string,
  norm: string,
  since: string,
): DiagEntry {
  return { code, component: "platform", source, action, human: { ru: human }, operator: { ru: operator }, norm, since };
}

/** Коды Платформы вне протоколов (РП42 п. 2): П3 и самопроверка при старте; `since` — версия пакета Платформы. */
export const PLATFORM_DIAG: Readonly<Record<PlatformCode, DiagEntry>> = {
  RESERVATION_RELEASED: platform("RESERVATION_RELEASED", ["platform"], "after_human",
    "Покупка не прошла: срок резерва истёк. Оформите покупку заново.",
    "Закрепление или повтор резерва по удержанию, освобождённому без закрепления (реверсал, отказ, проход expire); поздний клиринг — инцидент.", "РП41 п. 5, доп. п. 19", "0.6.0"),
  COMMIT_CONFLICT: platform("COMMIT_CONFLICT", ["platform"], "after_human",
    "Покупка не прошла по технической причине. Обратитесь в поддержку сервиса.",
    "Повтор закрепления с другой суммой по уже закреплённому удержанию: одно закрепление на удержание (РП41 п. 7).", "РП41 п. 5, п. 7", "0.6.0"),
  STARTUP_PARAMS_INVALID: platform("STARTUP_PARAMS_INVALID", ["environment"], "after_human", DOWN,
    "Стендовые параметры не прошли проверку loadParams: исправить config/params.stand.json или переменные среды.", "РП42 п. 4; PARAMS", "0.7.0"),
  STARTUP_PROXIES_INVALID: platform("STARTUP_PROXIES_INVALID", ["environment"], "after_human", DOWN,
    "PAO_TRUSTED_PROXIES — не адрес и не CIDR или префикс шире IPv4 /16, IPv6 /32.", "РП42 п. 4; РП32 п. 5", "0.7.0"),
  STARTUP_DB_REQUIRED: platform("STARTUP_DB_REQUIRED", ["environment"], "after_human", DOWN,
    "Среда sandbox без DATABASE_URL: задать адрес PostgreSQL.", "РП42 п. 4; РП30 п. 5", "0.7.0"),
  STARTUP_DB_MEMORY: platform("STARTUP_DB_MEMORY", ["environment"], "after_human",
    "Сервис работает в режиме разработки: данные не сохраняются после перезапуска.",
    "Среда dev без DATABASE_URL: хранилища в памяти, один процесс, повтор после перезапуска не ловится. Готовность не снимает.", "РП42 п. 4; РП30 п. 6", "0.7.0"),
  STARTUP_DB_MIGRATIONS: platform("STARTUP_DB_MIGRATIONS", ["environment"], "after_human", DOWN,
    "Миграции ядра и Платформы не применены: доступность PostgreSQL, права, журнал процесса.", "РП42 п. 4; РП30 п. 5", "0.7.0"),
  STARTUP_PARTICIPANTS_INVALID: platform("STARTUP_PARTICIPANTS_INVALID", ["environment"], "after_human", DOWN,
    "Доверенные ключи участников (PARTICIPANT_KEYS_PATH) не загружены: файл, формат, ключ эмулятора стенда или второй боевой участник.", "РП42 п. 4; РП36 п. 4", "0.7.0"),
  STARTUP_PAO_SPEC_MISMATCH: platform("STARTUP_PAO_SPEC_MISMATCH", ["platform"], "after_fix", DOWN,
    "Версия ПАО или PAO_SPEC_SHA256 agentic-core не равны Платформе: дефект сборки, подключить ядро с той же копией ПАО.", "РП42 п. 4; РП16", "0.7.0"),
  STARTUP_DIAG_INCOMPLETE: platform("STARTUP_DIAG_INCOMPLETE", ["platform"], "after_fix", DOWN,
    "Реестр кодов неполон или запись не по формату К17 (checkDiagRegistry): дефект сборки, дописать запись.", "РП42 п. 3–4", "0.7.0"),
};
