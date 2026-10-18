// Эмулятор окружения (agent) — SPEC §9, ПС23. Агент-получатель push-событий на стенде (РП40 п. 8): живёт в процессе
// под именем стенда, соединений не открывает. Ответы задаёт тест (например, 500, 500, затем 200); обработка
// идемпотентна по event_id (инвариант 9): повтор того же события учитывается как доставка, но не как новая обработка.
// До ПАО 1.5.0 событие не подписано (РП39 п. 6) — эмулятор подпись не проверяет.
import type { DeliveryTarget, EventTransport } from "../../pao/delivery.js";
import { STAND_PORT } from "../../pao/subscription.js";
import type { Event } from "../../shared/pao.js";

export const component = "env/agent";

/** Имя эмулятора агента-получателя на стенде — то же, что в `event_subscription_allow_hosts` стенда. */
export const STAND_AGENT_EMULATOR_HOST = "agent-emulator.stand";

/**
 * Адрес-заглушка эмулятора: глобальный одноадресный (адреса TEST-NET не глобальные и отвергаются, РП40 п. 3),
 * из блока IANA 192.0.32.0/20. Стенд по нему не соединяется.
 */
export const STAND_AGENT_EMULATOR_ADDRESS = "192.0.32.10";

/** Одна доставка, как её получил эмулятор. */
export interface ReceivedDelivery {
  readonly url: string;
  readonly event_id: string;
  readonly header_event_id: string | undefined;
  readonly event: Event;
  /** Ответ эмулятора на эту доставку. */
  readonly status: number;
}

export interface AgentReceiver {
  /** Транспорт стенда: доставка только эмулятору по проверенному адресу-заглушке, иначе сбой соединения. */
  readonly transport: EventTransport;
  /** Все доставки по порядку, включая неуспешные ответы. */
  readonly received: readonly ReceivedDelivery[];
  /** Обработанные события (ответ 2xx), каждое — один раз (идемпотентность по event_id). */
  readonly handled: readonly Event[];
  /** Ответы на следующие доставки по очереди; после очереди — 200. */
  respond(...statuses: number[]): void;
  reset(): void;
}

export function createAgentReceiver(): AgentReceiver {
  let queue: number[] = [];
  const received: ReceivedDelivery[] = [];
  const handled = new Map<string, Event>();
  const transport: EventTransport = async (t: DeliveryTarget, body, headers) => {
    if (t.host !== STAND_AGENT_EMULATOR_HOST || t.address !== STAND_AGENT_EMULATOR_ADDRESS) {
      throw new Error(`стенд: соединение вне эмулятора не открывается: ${t.host}`);
    }
    const event = JSON.parse(body) as Event;
    const status = queue.shift() ?? 200;
    received.push({ url: t.url, event_id: event.event_id, header_event_id: headers["x-event-id"], event, status });
    if (status >= 200 && status < 300 && !handled.has(event.event_id)) handled.set(event.event_id, event);
    return status;
  };
  // Метка стендового порта: рабочий сервер такой транспорт не принимает (РП40 п. 8).
  Object.defineProperty(transport, STAND_PORT, { value: true });
  return {
    transport,
    get received() {
      return [...received];
    },
    get handled() {
      return [...handled.values()];
    },
    respond(...statuses) {
      queue.push(...statuses);
    },
    reset() {
      queue = [];
      received.length = 0;
      handled.clear();
    },
  };
}
