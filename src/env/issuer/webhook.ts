// Эмулятор окружения (issuer) — приём вебхука-сигнала уведомлений клиента банком стенда (РП46 (б) п. 3, доп. п. 9 (о4)).
// Живёт в процессе под именем стенда, соединений не открывает (как агент-получатель, РП40 п. 8). Ответы задаёт тест;
// обработка идемпотентна по notification_id: повтор того же сигнала — доставка, но не новая обработка.
import type { DeliveryTarget, EventTransport } from "../../pao/delivery.js";
import { STAND_PORT } from "../../pao/subscription.js";

/** Имя приёмника вебхука банка стенда — то же, что в `participant_notify_allow_hosts` стенда. */
export const STAND_ISSUER_WEBHOOK_HOST = "issuer-emulator.stand";

/** Адрес-заглушка: глобальный одноадресный из блока IANA 192.0.32.0/20 (TEST-NET отвергается, РП40 п. 3). */
export const STAND_ISSUER_WEBHOOK_ADDRESS = "192.0.32.11";

/** notify_url банка стенда в записи доверенного участника. */
export const STAND_ISSUER_NOTIFY_URL = `https://${STAND_ISSUER_WEBHOOK_HOST}/notify`;

export interface ReceivedSignal {
  readonly url: string;
  readonly notification_id: string;
  readonly seq: number;
  readonly header_notification_id: string | undefined;
  readonly status: number;
}

export interface IssuerWebhookReceiver {
  /** Транспорт стенда: доставка только эмулятору по проверенному адресу-заглушке, иначе сбой соединения. */
  readonly transport: EventTransport;
  readonly received: readonly ReceivedSignal[];
  /** Обработанные сигналы (2xx), каждый notification_id — один раз. */
  readonly handled: readonly string[];
  /** Ответы на следующие доставки по очереди; после очереди — 200. */
  respond(...statuses: number[]): void;
}

export function createIssuerWebhookReceiver(): IssuerWebhookReceiver {
  const queue: number[] = [];
  const received: ReceivedSignal[] = [];
  const handled = new Set<string>();
  const transport: EventTransport = async (t: DeliveryTarget, body, headers) => {
    if (t.host !== STAND_ISSUER_WEBHOOK_HOST || t.address !== STAND_ISSUER_WEBHOOK_ADDRESS) {
      throw new Error(`стенд: соединение вне эмулятора не открывается: ${t.host}`);
    }
    const { notification_id, seq } = JSON.parse(body) as { notification_id: string; seq: number };
    const status = queue.shift() ?? 200;
    received.push({ url: t.url, notification_id, seq, header_notification_id: headers["x-notification-id"], status });
    if (status >= 200 && status < 300) handled.add(notification_id);
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
      return [...handled];
    },
    respond(...statuses) {
      queue.push(...statuses);
    },
  };
}
