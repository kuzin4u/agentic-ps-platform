// П9 Проверка тела изменяющих методов по схеме метода (РП31 п. 1): до обработчика и до захвата ключа идемпотентности.
// Схема — вручную; совпадение обязательных полей с agent-protocol.yaml сверяет tests/contract/pao-bodies.test.ts.
// Лишние поля игнорируются (ПАО §7): класс и уровень в теле не читаются, они — только из реестра (инвариант 5).

/** Обязательные поля тела `POST /pao/v1/agent/keys` — строки (ПАО 1.3.0). */
export const KEY_REGISTRATION_REQUIRED = ["alg", "public_key"] as const;

export interface KeyRegistration {
  readonly alg: string;
  readonly public_key: string;
}

/** Тело `POST /pao/v1/agent/keys` или undefined — тогда REQUEST_INVALID. Возвращаются только поля схемы. */
export function keyRegistrationBody(raw: string): KeyRegistration | undefined {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const o = v as Record<string, unknown>;
  const alg = Object.hasOwn(o, "alg") ? o.alg : undefined;
  const public_key = Object.hasOwn(o, "public_key") ? o.public_key : undefined;
  if (typeof alg !== "string" || typeof public_key !== "string") return undefined;
  return { alg, public_key };
}
