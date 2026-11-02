// Экран мандатов в приложении банка стенда (UI-К2; ROADMAP В1): эталонный модуль `src/ui/mandates/` с данными стенда.
// Эмулятор эмитента — банк: клиент уже опознан (на стенде — тест выдаёт ссылку входа по principal_ref), действия —
// подписью ключа stand:issuer-emulator по ПИ-8 того же сервера (как stand.issuer). Чтения — хранилища стенда в памяти
// (DECISIONS РП36 «Нюанс UI-К2 ч. 1»); для настоящего банка нужны чтения ПИ-8 — STATUS «Открыто».
import { createMandatesScreen, type MandatesScreen } from "../../ui/mandates/index.js";
import type { ScreenSessionTtl } from "../../ui/mandates/session.js";
import type { UiSettings } from "../../ui/shared/index.js";

/** Сроки входа на стенде (решение владельца 02.11: ссылка одноразовая и с коротким сроком). */
export const STAND_SCREEN_TTL: ScreenSessionTtl = { login_ttl_sec: 120, session_ttl_sec: 900 };

export interface IssuerScreenDeps {
  readonly now: () => Date;
  readonly settings?: UiSettings;
}

export function createIssuerScreen(deps: IssuerScreenDeps): MandatesScreen {
  return createMandatesScreen({ ttl: STAND_SCREEN_TTL, now: deps.now, ...(deps.settings ? { settings: deps.settings } : {}) });
}
