// Разрешение имени стенда (РП40 п. 8): проверка адреса подписки на стенде не отключается — подменяется только порт
// разрешения имени. Эмулятор агента-получателя живёт в процессе под именем STAND_AGENT_EMULATOR_HOST; стенд соединений
// не открывает (доставка стенда — в процессе), поэтому адрес-заглушка нужен только для проверки «адрес глобальный».
// Рабочий сервер этот модуль не импортирует (tests/unit/stand-boundary.test.ts): у него — системное разрешение имени.
import { STAND_AGENT_EMULATOR_ADDRESS, STAND_AGENT_EMULATOR_HOST } from "../env/agent/index.js";
import { STAND_PORT, type HostResolver } from "../pao/subscription.js";

export { STAND_AGENT_EMULATOR_ADDRESS, STAND_AGENT_EMULATOR_HOST };

/** Таблица имён стенда: тест подменяет адреса имени (подмена DNS) и возвращает исходные. */
export interface StandDns {
  readonly resolve: HostResolver;
  /** Адреса имени до reset(); пустой массив — имя не разрешается. */
  set(host: string, addresses: readonly string[]): void;
  reset(): void;
}

export function createStandDns(): StandDns {
  const initial = (): Map<string, readonly string[]> =>
    new Map([[STAND_AGENT_EMULATOR_HOST, [STAND_AGENT_EMULATOR_ADDRESS]]]);
  let table = initial();
  const resolve: HostResolver = async (host) => {
    const a = table.get(host);
    // Как системный lookup: имени нет — ENOTFOUND (отказ адреса, а не временный сбой).
    if (!a || a.length === 0) throw Object.assign(new Error(`стенд: имя не разрешается: ${host}`), { code: "ENOTFOUND" });
    return [...a];
  };
  // Метка стендового порта: шлюз без stand: true его не принимает (РП40 п. 8).
  Object.defineProperty(resolve, STAND_PORT, { value: true });
  return {
    resolve,
    set(host, addresses) {
      table.set(host, [...addresses]);
    },
    reset() {
      table = initial();
    },
  };
}
