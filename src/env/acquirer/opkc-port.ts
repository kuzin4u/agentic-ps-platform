// Порт эквайрера к ОПКЦ — каноническая модель ПИ §2, номера полей — [альбом] (РП6).
// Эмулятор ОПКЦ (маршрутизация, вызов ADP, ответ эмитента) — PS-11; до него — заглушка OpkcStub.
import type { CanonicalMessage } from "../../shared/canonical.generated.js";

/** Сообщение эквайрера: op_ref присваивает процессинг, а не эквайрер. */
export type AcquirerMessage = Omit<CanonicalMessage, "op_ref">;

export interface OpkcAuthResult {
  readonly op_ref: string;
  readonly approved: boolean;
  /** Код решения (ПИ §6) при отказе; при одобрении — null. */
  readonly reason: string | null;
}

export interface OpkcPort {
  authorize(msg: AcquirerMessage): Promise<OpkcAuthResult>;
  /** Реверсал по авторизации op_ref: признак — тот же, что в авторизации (A1 п. 5.1). */
  reverse(msg: CanonicalMessage): Promise<void>;
}

/** Заглушка ОПКЦ до PS-11: записывает сообщения, решение — из функции теста (по умолчанию одобрение). */
export class OpkcStub implements OpkcPort {
  readonly messages: CanonicalMessage[] = [];
  #seq = 0;

  constructor(
    private readonly decide: (msg: CanonicalMessage) => { approved: boolean; reason: string | null } = () => ({
      approved: true,
      reason: null,
    }),
  ) {}

  async authorize(msg: AcquirerMessage): Promise<OpkcAuthResult> {
    const op_ref = `OPKC-STUB-${String(++this.#seq).padStart(6, "0")}`;
    const full: CanonicalMessage = { op_ref, ...structuredClone(msg) };
    this.messages.push(full);
    const d = this.decide(full);
    return { op_ref, approved: d.approved, reason: d.approved ? null : d.reason };
  }

  async reverse(msg: CanonicalMessage): Promise<void> {
    this.messages.push(structuredClone(msg));
  }
}
