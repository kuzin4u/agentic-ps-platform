// П10 Уведомления клиента через банк (PS-20 ч. 3; РП46 (б), доп. п. 7, 9; A3 п. 5.3): Outbox участника и уведомитель по
// сохранённым записям операций ADP вне пути авторизации. Номер в ленте участника — под локом участника (как лента агента,
// РП39 п. 2); второе уведомление на то же событие отсекает notification_id из типа и ключа повтора. Только коды и ссылки:
// principal_ref, mandate_id, agent_code, op_ref, revocation_ref (инвариант 1, правило совместимости 3).
import { createHash } from "node:crypto";
import { canonicalJson } from "@kuzin4u/agentic-core";
import type { LimitSource, OperationNotify, OperationRecord, TxSqlClient } from "../adp/operations.js";
import type { Decision } from "../shared/canonical.generated.js";

export const NOTIFICATION_TYPES = [
  "client.mandate_first_use",
  "client.mandate_exhausted",
  "client.limit_exhausted",
  "client.limit_declined",
  "client.revoked_all",
] as const;
export type NotificationType = (typeof NOTIFICATION_TYPES)[number];

export interface NotificationData {
  readonly principal_ref: string;
  readonly mandate_id?: string;
  readonly agent_code?: string;
  readonly op_ref?: string;
  /** Чей предел у client.limit_declined (РП46 (б) п. 2). */
  readonly reason?: LimitSource;
  readonly revocation_ref?: string;
}

/** Что записать: тип, ключ повтора (операция, мандат, счёт периода, revocation_ref) и данные. Номер и id даёт запись. */
export interface NotificationDraft {
  readonly type: NotificationType;
  readonly key: string;
  readonly data: NotificationData;
}

export interface StoredNotification {
  readonly participant_code: string;
  readonly seq: number;
  readonly notification_id: string;
  readonly type: NotificationType;
  readonly at: string;
  readonly data: NotificationData;
}

/** Решённая запись операции с клиентом мандата — вход уведомителя. */
export interface NotifyOp {
  readonly op_ref: string;
  readonly decision: Decision;
  readonly mandate_id: string | null;
  readonly at: string;
  readonly notify: OperationNotify;
}

export const NOTIFICATION_ID_DOMAIN = "pao:participant-notification-id:v1";
export const NOTIFY_LOCK_DOMAIN = "pao:participant-notify-lock:v1";
export const NOTIFICATION_ID = /^ntf_[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** notification_id — `ntf_` + UUID v8 из участника, типа и ключа повтора: одно событие — один id на всех экземплярах. */
export function notificationIdFor(participant_code: string, type: NotificationType, key: string): string {
  if ([participant_code, key].some((v) => v === "" || v.includes("\n"))) throw new Error("notificationIdFor: участник или ключ");
  const b = createHash("sha256").update(`${NOTIFICATION_ID_DOMAIN}\n${participant_code}\n${type}\n${key}`, "utf8").digest().subarray(0, 16);
  b[6] = (b[6]! & 0x0f) | 0x80; // версия 8
  b[8] = (b[8]! & 0x3f) | 0x80; // вариант RFC 9562
  const h = b.toString("hex");
  return `ntf_${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Ключ pg_advisory_xact_lock участника: 64 бита SHA-256 со знаком, десятичной строкой (как ключ ленты агента). */
export function notifyLockKey(participant_code: string): string {
  return createHash("sha256").update(`${NOTIFY_LOCK_DOMAIN}\n${participant_code}`, "utf8").digest().readBigInt64BE(0).toString();
}

/** Решение, по которому могут быть уведомления: одобрение (первое использование, исчерпание лимита) или LIMIT_EXCEEDED. */
const notifiable = (d: Decision): boolean => d.decision === "APPROVE" || d.reason === "LIMIT_EXCEEDED";

/**
 * Уведомления по записи операции (РП46 (б) п. 2): APPROVE — первое использование мандата (ключ — мандат) и, если остаток
 * счёта клиента стал 0, исчерпание лимита клиента (ключ — счёт периода); LIMIT_EXCEEDED — отказ по превышению (ключ —
 * операция, одно на операцию при повторах агента).
 */
export function draftsFor(op: NotifyOp): NotificationDraft[] {
  const { principal_ref, agent_code } = op.notify;
  const mandate_id = op.mandate_id ?? undefined;
  const ref = { principal_ref, ...(mandate_id ? { mandate_id } : {}), agent_code };
  if (op.decision.decision === "APPROVE") {
    const out: NotificationDraft[] = [];
    if (mandate_id) out.push({ type: "client.mandate_first_use", key: mandate_id, data: ref });
    if (op.notify.client_account && op.notify.client_left_after === 0) {
      out.push({ type: "client.limit_exhausted", key: op.notify.client_account, data: { ...ref, op_ref: op.op_ref } });
    }
    return out;
  }
  if (op.decision.reason === "LIMIT_EXCEEDED") {
    const reason = op.notify.limit_source;
    return [{ type: "client.limit_declined", key: op.op_ref, data: { ...ref, op_ref: op.op_ref, ...(reason ? { reason } : {}) } }];
  }
  return [];
}

/** Курсор after — не уведомление этого участника (чужое или неизвестное — одинаково): 400 REQUEST_INVALID. */
export class NotificationCursorUnknown extends Error {
  constructor() {
    super("NOTIFICATION_CURSOR_UNKNOWN");
  }
}

/** Хранилище уведомлений участника; сбой — исключение. */
export interface ParticipantNotificationStore {
  /** Неразобранные решённые записи с клиентом, по которым могут быть уведомления, с at ≥ sinceAt, по возрастанию at. */
  pending(sinceAt: string, limit: number): Promise<readonly NotifyOp[]>;
  /** Самая старая неразобранная такая запись с at ≥ sinceAt — признак отставания уведомителя (доп. РП46 п. 9 (о2)). */
  oldestPending(sinceAt: string): Promise<string | undefined>;
  /** Одной транзакцией: лок участника, уведомления с ключом против повторов, отметка разбора записи операции. */
  settle(op: NotifyOp, drafts: readonly NotificationDraft[], at: string): Promise<void>;
  /** Уведомления не по записи операции (client.revoked_all): лок участника, ключ против повторов. */
  append(participant_code: string, drafts: readonly NotificationDraft[], at: string): Promise<void>;
  /** Лента участника после курсора, по возрастанию seq; чужой или неизвестный курсор — NotificationCursorUnknown. */
  page(participant_code: string, after: string | undefined, limit: number): Promise<readonly StoredNotification[]>;
}

/** Записи операций в памяти — источник уведомителя стенда (MemoryOperationStore.records). */
export interface OperationRecords {
  records(): Iterable<OperationRecord>;
}

const toNotifyOp = (r: OperationRecord): NotifyOp | undefined =>
  r.decision && r.notify && notifiable(r.decision)
    ? { op_ref: r.op_ref, decision: r.decision, mandate_id: r.mandate_id, at: r.at, notify: r.notify }
    : undefined;

/** В памяти (dev, стенд): один процесс — одна очередь; номер — по участнику, ключ против повторов — Map по id. */
export class MemoryParticipantNotificationStore implements ParticipantNotificationStore {
  readonly #byId = new Map<string, StoredNotification>();
  readonly #feeds = new Map<string, StoredNotification[]>();
  readonly #seen = new Set<string>();

  constructor(private readonly operations: OperationRecords) {}

  async pending(sinceAt: string, limit: number): Promise<readonly NotifyOp[]> {
    const out: NotifyOp[] = [];
    for (const r of this.operations.records()) {
      const op = toNotifyOp(r);
      if (op && op.at >= sinceAt && !this.#seen.has(op.op_ref)) out.push(op);
    }
    return out.sort((a, b) => (a.at === b.at ? (a.op_ref < b.op_ref ? -1 : 1) : a.at < b.at ? -1 : 1)).slice(0, limit);
  }

  async oldestPending(sinceAt: string): Promise<string | undefined> {
    return (await this.pending(sinceAt, 1))[0]?.at;
  }

  async settle(op: NotifyOp, drafts: readonly NotificationDraft[], at: string): Promise<void> {
    this.#insert(op.notify.participant_code, drafts, at);
    this.#seen.add(op.op_ref);
  }

  async append(participant_code: string, drafts: readonly NotificationDraft[], at: string): Promise<void> {
    this.#insert(participant_code, drafts, at);
  }

  async page(participant_code: string, after: string | undefined, limit: number): Promise<readonly StoredNotification[]> {
    const feed = this.#feeds.get(participant_code) ?? [];
    let from = 0;
    if (after !== undefined) {
      const cur = this.#byId.get(after);
      if (!cur || cur.participant_code !== participant_code) throw new NotificationCursorUnknown();
      from = cur.seq;
    }
    return feed.slice(from, from + limit).map((n) => structuredClone(n));
  }

  #insert(participant_code: string, drafts: readonly NotificationDraft[], at: string): void {
    const feed = this.#feeds.get(participant_code) ?? [];
    for (const d of drafts) {
      const notification_id = notificationIdFor(participant_code, d.type, d.key);
      if (this.#byId.has(notification_id)) continue;
      const n: StoredNotification = { participant_code, seq: feed.length + 1, notification_id, type: d.type, at, data: { ...d.data } };
      feed.push(n);
      this.#byId.set(notification_id, n);
    }
    this.#feeds.set(participant_code, feed);
  }
}

/** Точки внутри транзакции уведомления — только для тестов (гонка двух экземпляров): locked — сразу после лока участника. */
export interface PgNotificationHooks {
  readonly locked?: (participant_code: string) => Promise<void>;
}

interface PendingRow extends Record<string, unknown> {
  op_ref: string;
  decision: Decision;
  mandate_id: string | null;
  at: string;
  participant_code: string;
  principal_ref: string;
  agent_code: string;
  limit_source: LimitSource | null;
  client_account: string | null;
  client_left_after: string | null;
}

const PENDING_WHERE = `o.decision IS NOT NULL AND o.participant_code IS NOT NULL AND o.at >= $1
     AND (o.decision->>'decision' = 'APPROVE' OR o.decision->>'reason' = 'LIMIT_EXCEEDED')
     AND NOT EXISTS (SELECT 1 FROM participant_notify_seen s WHERE s.op_ref = o.op_ref)`;

/**
 * На PostgreSQL (sql/107): транзакция на запись операции — лок участника, seq = max + 1 у участника, вставка
 * ON CONFLICT (notification_id) DO NOTHING, отметка разбора, COMMIT. Лок держится до фиксации, поэтому N + 1
 * фиксируется только после N и курсор ленты не проскакивает незафиксированное (как РП39 п. 2).
 */
export class PgParticipantNotificationStore implements ParticipantNotificationStore {
  private readonly hooks: PgNotificationHooks;

  constructor(
    private readonly client: TxSqlClient,
    opts: { readonly hooks?: PgNotificationHooks } = {},
  ) {
    this.hooks = opts.hooks ?? {};
  }

  async pending(sinceAt: string, limit: number): Promise<readonly NotifyOp[]> {
    const r = await this.client.query<PendingRow>(
      `SELECT o.op_ref, o.decision, o.mandate_id, o.at, o.participant_code, o.principal_ref, o.agent_code, o.limit_source,
              o.client_account, o.client_left_after
         FROM adp_operations o
        WHERE ${PENDING_WHERE}
        ORDER BY o.at, o.op_ref
        LIMIT $2`,
      [sinceAt, limit],
    );
    return r.rows.map((row) => ({
      op_ref: row.op_ref,
      decision: row.decision,
      mandate_id: row.mandate_id,
      at: row.at,
      notify: {
        participant_code: row.participant_code,
        principal_ref: row.principal_ref,
        agent_code: row.agent_code,
        ...(row.limit_source ? { limit_source: row.limit_source } : {}),
        ...(row.client_account ? { client_account: row.client_account } : {}),
        ...(row.client_left_after === null ? {} : { client_left_after: Number(row.client_left_after) }),
      },
    }));
  }

  async oldestPending(sinceAt: string): Promise<string | undefined> {
    const r = await this.client.query<{ at: string | null }>(`SELECT min(o.at) AS at FROM adp_operations o WHERE ${PENDING_WHERE}`, [sinceAt]);
    return r.rows[0]?.at ?? undefined;
  }

  async settle(op: NotifyOp, drafts: readonly NotificationDraft[], at: string): Promise<void> {
    await this.tx(op.notify.participant_code, drafts, at, op.op_ref);
  }

  async append(participant_code: string, drafts: readonly NotificationDraft[], at: string): Promise<void> {
    await this.tx(participant_code, drafts, at);
  }

  async page(participant_code: string, after: string | undefined, limit: number): Promise<readonly StoredNotification[]> {
    let from = 0;
    if (after !== undefined) {
      const c = await this.client.query<{ seq: string }>(
        "SELECT seq FROM participant_notifications WHERE notification_id = $1 AND participant_code = $2",
        [after, participant_code],
      );
      if (!c.rows[0]) throw new NotificationCursorUnknown();
      from = Number(c.rows[0].seq);
    }
    const r = await this.client.query<{ seq: string; notification_id: string; type: NotificationType; at: string; data: string }>(
      `SELECT seq, notification_id, type, at, data FROM participant_notifications
        WHERE participant_code = $1 AND seq > $2 ORDER BY seq LIMIT $3`,
      [participant_code, from, limit],
    );
    return r.rows.map((row) => ({
      participant_code,
      seq: Number(row.seq),
      notification_id: row.notification_id,
      type: row.type,
      at: row.at,
      data: JSON.parse(row.data) as NotificationData,
    }));
  }

  private async tx(participant_code: string, drafts: readonly NotificationDraft[], at: string, op_ref?: string): Promise<void> {
    const tx = await this.client.connect();
    let broken: Error | undefined;
    try {
      try {
        await tx.query("BEGIN");
        void notifyLockKey; // ПОЛОМКА К3.4 (временно, откат следом): без лока прохода
        await this.hooks.locked?.(participant_code);
        for (const d of drafts) {
          await tx.query(
            `INSERT INTO participant_notifications (participant_code, seq, notification_id, type, at, data)
             SELECT $1, COALESCE(max(seq), 0) + 1, $2, $3, $4, $5 FROM participant_notifications WHERE participant_code = $1
             ON CONFLICT (notification_id) DO NOTHING`,
            [participant_code, notificationIdFor(participant_code, d.type, d.key), d.type, at, canonicalJson(d.data)],
          );
        }
        if (op_ref !== undefined) {
          await tx.query("INSERT INTO participant_notify_seen (op_ref, at) VALUES ($1, $2) ON CONFLICT (op_ref) DO NOTHING", [op_ref, at]);
        }
        await tx.query("COMMIT");
      } catch (err) {
        // Соединение, на котором не прошёл ROLLBACK, в пул не возвращается (как РП39).
        await tx.query("ROLLBACK").catch((rb: unknown) => {
          broken = rb instanceof Error ? rb : new Error(String(rb));
        });
        throw err;
      }
    } finally {
      tx.release(broken);
    }
  }
}

/** Сколько записей операций уведомитель разбирает за проход. */
export const NOTIFY_BATCH = 100;

export type NotifierLog = (level: "info" | "warn", fields: Record<string, unknown>, msg: string) => void;

export interface NotifierResult {
  readonly settled: number;
  readonly failed: number;
  /** Неразобранная запись старше половины горизонта (доп. РП46 п. 9 (о2)). */
  readonly lagging: boolean;
}

/**
 * Уведомитель (РП46 доп. п. 7): проход по решённым записям операций в горизонте вне пути авторизации. Сбой записи — в
 * журнал процесса, запись остаётся неразобранной и берётся следующим проходом.
 */
export class ParticipantNotifier {
  private readonly now: () => number;
  private readonly log: NotifierLog;

  constructor(
    private readonly store: ParticipantNotificationStore,
    private readonly opts: {
      readonly horizonSec: number;
      readonly now?: () => number;
      readonly log?: NotifierLog;
    },
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.log = opts.log ?? (() => {});
  }

  /** Признак отставания: самая старая неразобранная запись старше половины горизонта. */
  async lagging(): Promise<boolean> {
    const nowMs = this.now();
    const oldest = await this.store.oldestPending(new Date(nowMs - this.opts.horizonSec * 1000).toISOString());
    return oldest !== undefined && Date.parse(oldest) < nowMs - (this.opts.horizonSec * 1000) / 2;
  }

  async runOnce(): Promise<NotifierResult> {
    const nowMs = this.now();
    const since = new Date(nowMs - this.opts.horizonSec * 1000).toISOString();
    const at = new Date(nowMs).toISOString();
    let settled = 0;
    let failed = 0;
    for (const op of await this.store.pending(since, NOTIFY_BATCH)) {
      try {
        await this.store.settle(op, draftsFor(op), at);
        settled++;
      } catch {
        failed++;
        this.log("warn", { op_ref: op.op_ref, participant_code: op.notify.participant_code }, "П10: уведомление по записи операции не записано");
      }
    }
    const lagging = await this.lagging();
    if (lagging) this.log("warn", { code: "PARTICIPANT_NOTIFY_LAGGING" }, "П10: уведомитель отстаёт больше чем на половину горизонта");
    return { settled, failed, lagging };
  }
}

/** Проход уведомителя по таймеру; останов ждёт идущий проход. */
export function startParticipantNotifier(notifier: ParticipantNotifier, everyMs: number, onError: (err: unknown) => void): () => Promise<void> {
  let running: Promise<void> | undefined;
  const timer = setInterval(() => {
    if (running) return;
    running = notifier
      .runOnce()
      .then(
        () => undefined,
        (err: unknown) => onError(err),
      )
      .finally(() => (running = undefined));
  }, everyMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await running;
  };
}
