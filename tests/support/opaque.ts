// Случайные непрозрачные номера для тестов без цифровых прогонов (класс Р-160; РП53 «Нюансы тестов»): principal_ref
// с 7 и больше цифрами подряд отклоняется правилом формата (isOpaquePrincipalRef, src/consent/terms.ts — номер карты
// или телефона в поле), а хвост `randomUUID().slice(0, 8)` даёт такой прогон примерно в 5 % запусков — тест мигает.
// Хвост — только буквы a–f из UUID: ни одной цифры, правило формата не задевается при любом выпадении.
import { randomUUID } from "node:crypto";

/** Буквы a–f из UUID, ровно n знаков (UUID добирается, пока букв не хватает). */
export function letters(n = 8): string {
  let s = "";
  while (s.length < n) s += randomUUID().replace(/[^a-f]/g, "");
  return s.slice(0, n);
}

/** principal_ref для теста: `<prefix><8 букв>`, без цифр в случайной части. */
export const opaquePrincipalRef = (prefix = "prn_"): string => `${prefix}${letters()}`;
