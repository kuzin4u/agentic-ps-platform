// П1 Свой минимальный DER для УЦ песочницы (РП65 п. 2): строгий разбор — только определённая длина в кратчайшей записи,
// однобайтовые теги, без байтов после конца, вложенность не глубже MAX_DEPTH; запись — ровно то, что нужно шаблону
// сертификата. Сторонних библиотек нет: подпись и ключи — node:crypto.

/** Предел вложенности при разборе (РП65 п. 2). */
export const MAX_DEPTH = 8;

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerError";
  }
}

/** Элемент TLV внутри буфера: тег, начало заголовка, начало и конец содержимого. */
export interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly contentStart: number;
  readonly end: number;
}

export const constructed = (tag: number): boolean => (tag & 0x20) !== 0;

/**
 * Один TLV с позиции pos, не дальше limit. Длинная форма длины — не больше двух байт и только когда короткой не хватает;
 * неопределённая длина (0x80) и многобайтовый тег — отказ.
 */
export function readTlv(buf: Uint8Array, pos: number, limit: number): Tlv {
  if (pos + 2 > limit) throw new DerError("обрезано: нет заголовка");
  const tag = buf[pos]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("многобайтовый тег");
  const first = buf[pos + 1]!;
  let len: number;
  let header: number;
  if (first < 0x80) {
    len = first;
    header = 2;
  } else if (first === 0x81) {
    if (pos + 3 > limit) throw new DerError("обрезано: длина");
    len = buf[pos + 2]!;
    if (len < 0x80) throw new DerError("длина не в кратчайшей записи");
    header = 3;
  } else if (first === 0x82) {
    if (pos + 4 > limit) throw new DerError("обрезано: длина");
    len = (buf[pos + 2]! << 8) | buf[pos + 3]!;
    if (len < 0x100) throw new DerError("длина не в кратчайшей записи");
    header = 4;
  } else {
    throw new DerError("длина: неопределённая или длиннее двух байт");
  }
  const contentStart = pos + header;
  const end = contentStart + len;
  if (end > limit) throw new DerError("обрезано: содержимое");
  return { tag, start: pos, contentStart, end };
}

/** Дети составного элемента: подряд, ровно до его конца. */
export function children(buf: Uint8Array, parent: Tlv): Tlv[] {
  if (!constructed(parent.tag)) throw new DerError("ожидался составной элемент");
  const out: Tlv[] = [];
  for (let pos = parent.contentStart; pos < parent.end; ) {
    const t = readTlv(buf, pos, parent.end);
    out.push(t);
    pos = t.end;
  }
  return out;
}

/**
 * Весь буфер — ровно один элемент; дерево обходится целиком, но строгость — только запись TLV (РП65 нюанс 5): длины,
 * однобайтовые теги, хвосты и вложенность. Содержимое примитивов (INTEGER, BOOLEAN, строки) и составные формы строк не
 * проверяются — в субъекте и атрибутах CSR они не читаются и закрыты подписью. Глубина (нюанс 6): корень — 1, составной
 * элемент на глубине MAX_DEPTH — отказ, даже пустой.
 */
export function parseStrict(buf: Uint8Array): Tlv {
  const root = readTlv(buf, 0, buf.length);
  if (root.end !== buf.length) throw new DerError("байты после конца");
  const walk = (t: Tlv, depth: number): void => {
    if (!constructed(t.tag)) return;
    if (depth >= MAX_DEPTH) throw new DerError("вложенность глубже предела");
    for (const c of children(buf, t)) walk(c, depth + 1);
  };
  walk(root, 1);
  return root;
}

export const bytesOf = (buf: Uint8Array, t: Tlv): Buffer => Buffer.from(buf.subarray(t.start, t.end));
export const contentOf = (buf: Uint8Array, t: Tlv): Buffer => Buffer.from(buf.subarray(t.contentStart, t.end));

// --- Запись ---

const lengthBytes = (n: number): number[] => {
  if (n < 0x80) return [n];
  if (n < 0x100) return [0x81, n];
  if (n < 0x10000) return [0x82, n >> 8, n & 0xff];
  throw new DerError("длина больше 65 535");
};

export const tlv = (tag: number, ...parts: readonly Uint8Array[]): Buffer => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag, ...lengthBytes(body.length)]), body]);
};

export const seq = (...parts: readonly Uint8Array[]): Buffer => tlv(0x30, ...parts);
export const set = (...parts: readonly Uint8Array[]): Buffer => tlv(0x31, ...parts);
/** [n] EXPLICIT — составной контекстный тег. */
export const explicit = (n: number, ...parts: readonly Uint8Array[]): Buffer => tlv(0xa0 | n, ...parts);
export const bitString = (bytes: Uint8Array, unusedBits = 0): Buffer => tlv(0x03, Buffer.from([unusedBits]), bytes);
export const octetString = (bytes: Uint8Array): Buffer => tlv(0x04, bytes);
export const utf8 = (s: string): Buffer => tlv(0x0c, Buffer.from(s, "utf8"));
export const BOOLEAN_TRUE = Buffer.from([0x01, 0x01, 0xff]);

/** INTEGER из положительного числа без знака в байтах: ведущие нули снимаются, при старшем бите — один 0x00. */
export const uint = (bytes: Uint8Array): Buffer => {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const v = Buffer.from(bytes.subarray(i));
  return tlv(0x02, (v[0]! & 0x80) !== 0 ? Buffer.concat([Buffer.from([0]), v]) : v);
};

/** OID из записи «1.2.840…». */
export const oid = (dotted: string): Buffer => {
  const arcs = dotted.split(".").map((a) => {
    if (!/^(0|[1-9]\d*)$/.test(a)) throw new DerError(`OID: ${dotted}`);
    return Number(a);
  });
  if (arcs.length < 2 || arcs[0]! > 2 || (arcs[0]! < 2 && arcs[1]! > 39)) throw new DerError(`OID: ${dotted}`);
  const out: number[] = [];
  for (const arc of [arcs[0]! * 40 + arcs[1]!, ...arcs.slice(2)]) {
    const groups: number[] = [];
    let v = arc;
    do {
      groups.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let g = 0; g < groups.length - 1; g++) groups[g]! |= 0x80;
    out.push(...groups);
  }
  return tlv(0x06, Buffer.from(out));
};

/** Время сертификата (RFC 5280 §4.1.2.5): UTCTime до 2049 года, GeneralizedTime с 2050-го; секунды, «Z». */
export const time = (d: Date): Buffer => {
  const iso = d.toISOString();
  const digits = iso.slice(0, 19).replace(/[-:T]/g, "");
  const year = d.getUTCFullYear();
  if (year < 1950 || year > 9999) throw new DerError(`год вне диапазона: ${year}`);
  return year < 2050 ? tlv(0x17, Buffer.from(`${digits.slice(2)}Z`, "ascii")) : tlv(0x18, Buffer.from(`${digits}Z`, "ascii"));
};
