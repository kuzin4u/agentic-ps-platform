// П5 Агентские реквизиты (SPEC §3, РП47): записи токена и реквизита, порты токен-сервиса (ПИ-4) и банка клиента.
// Номера карты нет нигде (инвариант 1): у токена — только funding_ref банка, у реквизита — SHA-256 криптограммы, а не она.
import { createHash, randomInt } from "node:crypto";

/** Наборы допустимых MCC продавцов области CART (РП49 (д) п. 2): merchant_id → набор из справочника оператора. */
export type MerchantMcc = Readonly<Record<string, readonly string[]>>;

/** Домен агентского токена (РП47 п. 2): из записи CART журнала, а не со слов агента (инвариант 5). */
export interface TokenDomain {
  readonly agent_code: string;
  /** Мандат CART: один токен на CART. */
  readonly mandate_id: string;
  readonly merchant_scope: readonly string[];
  readonly valid_to: string;
  /** Набор MCC на каждого продавца merchant_scope — из справочника продавцов при выпуске, не со слов агента. */
  readonly merchant_mcc: MerchantMcc;
}

export interface TokenRecord extends Omit<TokenDomain, "merchant_mcc"> {
  /** null — токен выпущен до sql/110 (РП49 (д) п. 5): ADP не подтверждает операцию по нему. */
  readonly merchant_mcc: MerchantMcc | null;
  readonly token_ref: string;
  /** Ссылка банка на карту клиента (ПИ-4); номера карты у Платформы нет. */
  readonly funding_ref: string;
  readonly created_at: string;
}

/** Статус записи реквизита; EXPIRED вычисляется при чтении по valid_to (часы Платформы), REVOKED — с PS-17. */
export type CredentialRecordStatus = "ISSUED" | "USED";

export interface CredentialRecord {
  readonly credential_ref: string;
  readonly agent_code: string;
  readonly mandate_id: string;
  readonly token_ref: string;
  readonly order_ref: string;
  readonly merchant_id: string;
  readonly amount_max: number;
  readonly currency: string;
  readonly valid_to: string;
  /** SHA-256 (hex) криптограммы: значение пересчитывает токен-сервис (РП47 п. 3). */
  readonly cryptogram_sha256: string;
  readonly status: CredentialRecordStatus;
  /** Операция, погасившая реквизит (РП47 п. 8): связь реквизита с операцией для сверки продавца (РП22 п. 6). */
  readonly op_ref: string | null;
  readonly created_at: string;
}

/** Вход криптограммы на заказ (ПИ-4): поля, над которыми токен-сервис считает HMAC. */
export interface CryptogramInput {
  readonly token_ref: string;
  readonly order_ref: string;
  readonly merchant_id: string;
  readonly amount_max: number;
  readonly currency: string;
  readonly valid_to: string;
}

/** Порт токен-сервиса (ПИ-4) на канонической модели; формат сети — в адаптере (РП6). Сбой — исключение. */
export interface TokenServicePort {
  issueToken(input: { readonly funding_ref: string; readonly domain: TokenDomain }): Promise<{ readonly token_ref: string }>;
  cryptogram(input: CryptogramInput): Promise<string>;
}

/**
 * Справочник продавцов оператора (РП49 (д) п. 1): набор допустимых MCC продавца. Локальное чтение, не внешний вызов П5
 * (п. 3). Продавца нет — undefined; сбой — исключение. На стенде — эмулятор продавцов, в бою — справочник эквайреров
 * оператора, форма — [альбом] (РП6).
 */
export interface MerchantDirectory {
  mccOf(merchant_id: string): Promise<readonly string[] | undefined>;
}

/** MCC — ровно четыре цифры (решение владельца 21.10, «Нюансы РП49» п. 9); не по форме — справочник не прочитан. */
export const MCC = /^[0-9]{4}$/;

/** Банк клиента мандата (порт участника, РП36): ссылка на карту клиента для выпуска токена. Сбой — исключение. */
export interface FundingSource {
  fundingRef(client: { readonly participant_code: string; readonly principal_ref: string }): Promise<string>;
}

export const sha256Hex = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

const LETTERS = "abcdefghijklmnopqrstuvwxyz";

/**
 * Непрозрачная ссылка: префикс и 24 строчные латинские буквы. Без цифр — длинная цифровая серия не похожа на номер
 * карты и не задевает правило непрозрачных ссылок (инвариант 1, STATUS «Открыто» о семи цифрах). Буква — randomInt
 * (отбор без смещения), а не «байт % 26»: 256 на 26 не делится (CodeQL js/biased-cryptographic-random).
 */
export function opaqueRef(prefix: string): string {
  let s = prefix;
  for (let i = 0; i < 24; i++) s += LETTERS[randomInt(LETTERS.length)];
  return s;
}

export const CREDENTIAL_REF = /^crd_[a-z]{24}$/;
