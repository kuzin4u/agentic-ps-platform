import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AgentExcludedError,
  AgentKeys,
  AgentNotFoundError,
  AgentRegistry,
  ConcurrentChangeError,
  DEFAULT_KEY_ALGORITHMS,
  ED25519,
  InMemoryAgentRegistryStore,
  KEY_STATUSES_MATCH_PAO,
  KeyInvalidError,
  KeyNotFoundError,
  KeyTakenError,
  isWeakEd25519,
  jwkThumbprint,
  parseKey,
  type AdmissionDecision,
  type AgentKey,
  type AgentRegistryStore,
  type KeyPolicy,
} from "../../src/registry/index.js";

// Эталон RFC 8037 прил. A.3: открытый ключ Ed25519 и его отпечаток по RFC 7638 (РП23 п. 3).
const RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_KID = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
// Тот же ключ в виде public_key ПАО: DER SubjectPublicKeyInfo (префикс Ed25519 + 32 байта x), base64.
const RFC8037_SPKI = Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"),
  Buffer.from(RFC8037_X, "base64url"),
]).toString("base64");

const NOW = new Date("2026-10-11T12:00:00Z");
const DAY = 86_400_000;
const at = (days: number): Date => new Date(NOW.getTime() + days * DAY);
const POLICY: KeyPolicy = { key_ttl_days: 90, key_overlap_days: 7 };
const OPERATOR = "buyref-operator";
const CODE = "nspk:agent:buyref-01:v3";

const newPublicKey = (type: "ed25519" | "x25519" = "ed25519"): string =>
  generateKeyPairSync(type as "ed25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");

const application = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  agent_code: CODE,
  class: "BUYER",
  model: "buyer-agent-ref",
  runtime: "node-20",
  alg: "ed25519",
  public_key: newPublicKey(),
  ...over,
});

/** Реестр и ключи на общем хранилище с управляемыми часами. */
function stand(policy: KeyPolicy = POLICY) {
  let clock = NOW;
  const store = new InMemoryAgentRegistryStore();
  const now = (): Date => clock;
  const registry = new AgentRegistry(store, { keys: policy, now });
  const keys = new AgentKeys(store, { keys: policy, now });
  const admit = (over: Record<string, unknown> = {}): AgentKey => {
    const d = registry.admit(application(over), { contour: "sandbox", operator: OPERATOR });
    expect(d).toMatchObject({ admitted: true });
    return (d as { key: AgentKey }).key;
  };
  return { store, registry, keys, admit, setClock: (d: Date) => (clock = d) };
}

/** Хранилище-обёртка: все методы делегируются, кроме подменённых (гонка между чтением и записью). */
const wrap = (store: AgentRegistryStore, over: Partial<AgentRegistryStore>): AgentRegistryStore => ({
  get: (c) => store.get(c),
  ownerOf: (i, id) => store.ownerOf(i, id),
  insert: (r, k) => store.insert(r, k),
  updateStatus: (c, v, f) => store.updateStatus(c, v, f),
  getKey: (kid) => store.getKey(kid),
  keysOf: (c) => store.keysOf(c),
  addKey: (k, e, sh) => store.addKey(k, e, sh),
  revokeKey: (kid, v, at) => store.revokeKey(kid, v, at),
  ...over,
});

const reasons = (d: AdmissionDecision): readonly string[] => (d.admitted ? [] : d.reasons);

describe("kid — отпечаток JWK по RFC 7638 (РП23 п. 3)", () => {
  it("эталон RFC 8037 прил. A.3: канонизация {crv,kty,x}, SHA-256, base64url без дополнения", () => {
    expect(jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: RFC8037_X })).toBe(RFC8037_KID);
    expect(jwkThumbprint({ x: RFC8037_X, kty: "OKP", crv: "Ed25519" })).toBe(RFC8037_KID);
  });

  it("тот же эталон через public_key ПАО: DER SPKI → JWK → kid", () => {
    expect(ED25519.toJwk(RFC8037_SPKI)).toEqual({ crv: "Ed25519", kty: "OKP", x: RFC8037_X });
    expect(parseKey([ED25519], "ed25519", RFC8037_SPKI)).toEqual({
      kid: RFC8037_KID,
      alg: "ed25519",
      public_key: RFC8037_SPKI,
    });
  });

  it("допуск с эталонным ключом выдаёт эталонный kid", () => {
    expect(stand().admit({ public_key: RFC8037_SPKI }).kid).toBe(RFC8037_KID);
  });

  it.each([
    ["base64url вместо base64", RFC8037_SPKI.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") + "_"],
    ["без дополнения", RFC8037_SPKI.replace(/=+$/, "")],
    ["с пробелом", ` ${RFC8037_SPKI}`],
    ["с переводом строки", `${RFC8037_SPKI.slice(0, 20)}\n${RFC8037_SPKI.slice(20)}`],
    ["ключ X25519", newPublicKey("x25519")],
    ["32 байта без SPKI", Buffer.from(RFC8037_X, "base64url").toString("base64")],
    ["лишний байт после DER", Buffer.concat([Buffer.from(RFC8037_SPKI, "base64"), Buffer.from([0])]).toString("base64")],
  ])("неканоничная запись или не Ed25519 — не разбирается: %s", (_name, pk) => {
    expect(ED25519.toJwk(pk)).toBeNull();
    expect(parseKey([ED25519], "ed25519", pk)).toBeNull();
  });

  it("alg вне перечня контура — не разбирается (fail-closed)", () => {
    expect(parseKey([ED25519], "ED25519", RFC8037_SPKI)).toBeNull();
    expect(parseKey([], "ed25519", RFC8037_SPKI)).toBeNull();
    expect(parseKey([ED25519], undefined, RFC8037_SPKI)).toBeNull();
  });
});

describe("слабые ключи Ed25519 — KEY_INVALID (аудит PS-04 №1, A2 п. 5.1, РП23 п. 2)", () => {
  const spkiOf = (hex: string): string =>
    Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]).toString("base64");
  // Восемь точек малого порядка — независимый список (как блок-лист libsodium), не из кода Платформы.
  const SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  ];
  // Неканоническая запись: нейтраль и −1 со знаковым битом при x = 0; y = p + 1 и y = p.
  const NON_CANONICAL = [
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ];

  it("почему блокер: с ключом-нейтралью подпись «R = нейтраль, S = 0» верна для любого сообщения", () => {
    const pub = createPublicKey({ key: Buffer.from(spkiOf(SMALL_ORDER[0]!), "base64"), format: "der", type: "spki" });
    const forged = Buffer.concat([Buffer.from(SMALL_ORDER[0]!, "hex"), Buffer.alloc(32)]);
    expect(verify(null, Buffer.from("любое обращение"), pub, forged)).toBe(true);
  });

  it.each(SMALL_ORDER)("точка малого порядка %s — слабая, не разбирается", (hex) => {
    expect(isWeakEd25519(Buffer.from(hex, "hex"))).toBe(true);
    expect(parseKey([ED25519], "ed25519", spkiOf(hex))).toBeNull();
  });

  it.each(NON_CANONICAL)("неканоническая запись %s — слабая", (hex) => {
    expect(isWeakEd25519(Buffer.from(hex, "hex"))).toBe(true);
  });

  it("эталон RFC 8037 и случайные ключи — не слабые", () => {
    expect(isWeakEd25519(Buffer.from(RFC8037_X, "base64url"))).toBe(false);
    for (let i = 0; i < 50; i++) {
      const x = Buffer.from(newPublicKey(), "base64").subarray(12);
      expect(isWeakEd25519(x)).toBe(false);
    }
  });

  it("допуск со слабым ключом — KEY_INVALID, ничего не сохранено; register — KeyInvalidError", () => {
    const s = stand();
    const d = s.registry.admit(application({ public_key: spkiOf(SMALL_ORDER[0]!) }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(s.store.get(CODE)).toBeUndefined();
    s.admit();
    for (const hex of SMALL_ORDER) {
      expect(() => s.keys.register(CODE, { alg: "ed25519", public_key: spkiOf(hex) })).toThrow(KeyInvalidError);
    }
    expect(s.keys.list(CODE)).toHaveLength(1);
  });
});

describe("первый ключ при допуске (РП23 п. 2)", () => {
  it("ключ сохраняется вместе с записью: kid, срок key_ttl_days, ACTIVE", () => {
    const s = stand();
    const key = s.admit();
    expect(key).toMatchObject({
      agent_code: CODE,
      alg: "ed25519",
      valid_from: NOW.toISOString(),
      valid_to: at(90).toISOString(),
      revoked_at: null,
    });
    expect(s.keys.list(CODE)).toEqual([
      {
        kid: key.kid,
        alg: "ed25519",
        public_key: key.public_key,
        valid_from: NOW.toISOString(),
        valid_to: at(90).toISOString(),
        status: "ACTIVE",
      },
    ]);
    expect(s.keys.lookup(CODE, key.kid)).toEqual({ alg: "ed25519", publicKey: key.public_key, status: "ACTIVE" });
  });

  it("ключ, уже зарегистрированный у другого агента, — KEY_INVALID, агент не сохранён", () => {
    const s = stand();
    const key = s.admit();
    const other = "nspk:agent:other-01:v1";
    const d = s.registry.admit(application({ agent_code: other, public_key: key.public_key }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(s.registry.get(other)).toBeUndefined();
  });

  it.each([
    ["ключ другого агента", (k: AgentKey) => k.public_key],
    ["неразборчивый ключ", () => "AAAA"],
    ["ключ X25519", () => newPublicKey("x25519")],
  ])("KEY_INVALID при допуске (%s): в хранилище нет ни записи, ни владельца, ни ключа", (_n, pk) => {
    const s = stand();
    const existing = s.admit();
    const other = "nspk:agent:other-01:v1";
    const publicKey = pk(existing);
    const d = s.registry.admit(application({ agent_code: other, public_key: publicKey }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(s.store.get(other)).toBeUndefined();
    expect(s.store.ownerOf("nspk:agent", "other-01")).toBeUndefined();
    expect(s.store.keysOf(other)).toEqual([]);
    expect(s.store.getKey(existing.kid)).toEqual(existing);
    expect(s.store.keysOf(CODE)).toEqual([existing]);
    const parsed = parseKey([ED25519], "ed25519", publicKey);
    if (parsed && parsed.kid !== existing.kid) expect(s.store.getKey(parsed.kid)).toBeUndefined();
  });

  it("контур оператора: до точки расширения ГОСТ (РП5) ed25519 не принимается — KEY_INVALID", () => {
    expect(DEFAULT_KEY_ALGORITHMS.operator).toEqual([]);
    const d = stand().registry.admit(application({ conformance_run_ref: "RUN-77" }), {
      contour: "operator",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
  });

  it("неделимость в хранилище: kid занят — не сохраняется ни запись, ни ключ", () => {
    const s = stand();
    const key = s.admit();
    const d = stand().registry.admit(application({ agent_code: "nspk:agent:other-01:v1" }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    const rec = (d as { record: Parameters<InMemoryAgentRegistryStore["insert"]>[0] }).record;
    const clash = { ...key, agent_code: rec.agent_code };
    expect(() => s.store.insert(rec, clash)).toThrow(KeyTakenError);
    expect(s.store.get(rec.agent_code)).toBeUndefined();
    expect(s.store.ownerOf(rec.issuer, rec.id)).toBeUndefined();
    expect(s.store.keysOf(rec.agent_code)).toEqual([]);
  });

  it("конкурентная регистрация того же ключа между проверкой и вставкой — KEY_INVALID, а не исключение", () => {
    const s = stand();
    const pk = newPublicKey();
    const kid = (parseKey([ED25519], "ed25519", pk) as { kid: string }).kid;
    const racing = wrap(s.store, {
      getKey: () => undefined,
      insert: (record, firstKey) => {
        const racer = "nspk:agent:racer-01:v1";
        s.store.insert({ ...record, agent_code: racer, id: "racer-01" }, { ...firstKey, agent_code: racer });
        s.store.insert(record, firstKey);
      },
    });
    const d = new AgentRegistry(racing, { keys: POLICY, now: () => NOW }).admit(application({ public_key: pk }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(s.store.getKey(kid)?.agent_code).toBe("nspk:agent:racer-01:v1");
    expect(s.store.get(CODE)).toBeUndefined();
  });
});

describe("регистрация ключа и перекрытие (A2 п. 5.3, РП23 п. 4)", () => {
  it("новый ключ — срок key_ttl_days; прежний сокращается до now + key_overlap_days", () => {
    const s = stand();
    const first = s.admit();
    s.setClock(at(30));
    const second = s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect(second.valid_to).toBe(at(120).toISOString());
    expect(s.store.getKey(first.kid)?.valid_to).toBe(at(37).toISOString());
    expect(s.keys.list(CODE).map((k) => k.status)).toEqual(["ACTIVE", "ACTIVE"]);
    s.setClock(new Date(at(37).getTime() - 1));
    expect(s.keys.lookup(CODE, first.kid)?.status).toBe("ACTIVE");
    s.setClock(at(37));
    expect(s.keys.lookup(CODE, first.kid)?.status).toBe("EXPIRED");
    expect(s.keys.lookup(CODE, second.kid)?.status).toBe("ACTIVE");
  });

  it("первый ключ истекает по key_ttl_days на подставленных часах: за 1 мс — ACTIVE, в valid_to — EXPIRED", () => {
    const s = stand();
    const key = s.admit();
    s.setClock(new Date(at(90).getTime() - 1));
    expect(s.keys.lookup(CODE, key.kid)?.status).toBe("ACTIVE");
    s.setClock(at(90));
    expect(s.keys.lookup(CODE, key.kid)?.status).toBe("EXPIRED");
    expect(s.keys.list(CODE)[0]?.status).toBe("EXPIRED");
    expect(s.store.getKey(key.kid)).toEqual(key);
  });

  it("key_overlap_days = 0 — прежний ключ истекает сразу", () => {
    const s = stand({ key_ttl_days: 90, key_overlap_days: 0 });
    const first = s.admit();
    s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect(s.keys.lookup(CODE, first.kid)?.status).toBe("EXPIRED");
  });

  it("срок короче перекрытия не продлевается; отозванный и истёкший не трогаются", () => {
    const s = stand();
    const first = s.admit();
    s.setClock(at(86));
    const second = s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect(s.store.getKey(first.kid)?.valid_to).toBe(at(90).toISOString());
    s.keys.revoke(CODE, second.kid);
    s.setClock(at(91));
    const revokedBefore = s.store.getKey(second.kid);
    s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect(s.store.getKey(first.kid)?.valid_to).toBe(at(90).toISOString());
    expect(s.store.getKey(second.kid)).toEqual(revokedBefore);
  });

  it.each([
    ["свой действующий", (k: AgentKey) => k.public_key],
    ["неразборчивый", () => "AAAA"],
  ])("повтор или неверный ключ — KeyInvalidError: %s", (_n, pk) => {
    const s = stand();
    const first = s.admit();
    expect(() => s.keys.register(CODE, { alg: "ed25519", public_key: pk(first) })).toThrow(KeyInvalidError);
    expect(() => s.keys.register(CODE, { alg: "rsa", public_key: newPublicKey() })).toThrow(KeyInvalidError);
    expect(() => s.keys.register(CODE, null)).toThrow(KeyInvalidError);
    expect(s.keys.list(CODE)).toHaveLength(1);
  });

  it("отозванный ключ повторно не регистрируется: kid не возвращается (РП23 п. 5)", () => {
    const s = stand();
    const first = s.admit();
    s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    s.keys.revoke(CODE, first.kid);
    expect(() => s.keys.register(CODE, { alg: "ed25519", public_key: first.public_key })).toThrow(KeyInvalidError);
    expect(s.keys.lookup(CODE, first.kid)?.status).toBe("REVOKED");
  });

  it("отозванный ключ не регистрируется другому агенту — ни через register, ни через допуск", () => {
    const s = stand();
    const first = s.admit();
    s.keys.revoke(CODE, first.kid);
    const other = "nspk:agent:other-01:v1";
    s.admit({ agent_code: other });
    expect(() => s.keys.register(other, { alg: "ed25519", public_key: first.public_key })).toThrow(KeyInvalidError);
    const third = "nspk:agent:third-01:v1";
    const d = s.registry.admit(application({ agent_code: third, public_key: first.public_key }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(s.store.get(third)).toBeUndefined();
    expect(s.store.getKey(first.kid)).toMatchObject({ agent_code: CODE, revoked_at: NOW.toISOString() });
    expect(s.keys.lookup(other, first.kid)).toBeUndefined();
  });

  it("ключ другого агента — KeyInvalidError", () => {
    const s = stand();
    const first = s.admit();
    s.admit({ agent_code: "nspk:agent:other-01:v1" });
    expect(() =>
      s.keys.register("nspk:agent:other-01:v1", { alg: "ed25519", public_key: first.public_key }),
    ).toThrow(KeyInvalidError);
  });

  it("агента нет — AgentNotFoundError; исключён — AgentExcludedError; приостановлен — можно", () => {
    const s = stand();
    expect(() => s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).toThrow(AgentNotFoundError);
    s.admit();
    s.registry.changeStatus(CODE, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    expect(s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() }).agent_code).toBe(CODE);
    s.registry.changeStatus(CODE, { to: "EXCLUDED", ground: "KEY_COMPROMISE" });
    expect(() => s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).toThrow(AgentExcludedError);
  });

  it("конкурентная регистрация: набор ключей агента изменился после чтения — ни один ключ не добавлен", () => {
    const s = stand();
    const first = s.admit();
    const expected = new Map([[first.kid, first.row_version]]);
    s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    const pk = parseKey([ED25519], "ed25519", newPublicKey()) as { kid: string; alg: string; public_key: string };
    const late: AgentKey = { ...first, ...pk, row_version: 1 };
    expect(s.store.addKey(late, expected, new Map())).toBe(false);
    expect(s.store.getKey(pk.kid)).toBeUndefined();
    expect(s.keys.list(CODE)).toHaveLength(2);
  });

  it("конкурентная регистрация через сервис — ConcurrentChangeError", () => {
    const s = stand();
    s.admit();
    const racing = wrap(s.store, {
      addKey: (key, expected, shorten) => {
        s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
        return s.store.addKey(key, expected, shorten);
      },
    });
    const keys = new AgentKeys(racing, { keys: POLICY, now: () => NOW });
    expect(() => keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).toThrow(ConcurrentChangeError);
    expect(s.keys.list(CODE)).toHaveLength(2);
  });
});

describe("отзыв ключа (A2 п. 5.4, РП23 п. 5)", () => {
  it("отзыв действует сразу: статус REVOKED на следующей проверке; повторный отзыв — тот же ключ", () => {
    const s = stand();
    const key = s.admit();
    s.setClock(at(1));
    const revoked = s.keys.revoke(CODE, key.kid);
    expect(revoked).toMatchObject({ kid: key.kid, revoked_at: at(1).toISOString() });
    expect(s.keys.lookup(CODE, key.kid)?.status).toBe("REVOKED");
    s.setClock(at(2));
    expect(s.keys.revoke(CODE, key.kid)).toEqual(revoked);
  });

  it("можно отозвать последний действующий ключ", () => {
    const s = stand();
    const key = s.admit();
    s.keys.revoke(CODE, key.kid);
    expect(s.keys.list(CODE).filter((k) => k.status === "ACTIVE")).toEqual([]);
  });

  it("отзыв истёкшего ключа — REVOKED", () => {
    const s = stand();
    const key = s.admit();
    s.setClock(at(91));
    expect(s.keys.lookup(CODE, key.kid)?.status).toBe("EXPIRED");
    s.keys.revoke(CODE, key.kid);
    expect(s.keys.lookup(CODE, key.kid)?.status).toBe("REVOKED");
  });

  it("чужой kid — KeyNotFoundError, ключ другого агента не отзывается", () => {
    const s = stand();
    const key = s.admit();
    s.admit({ agent_code: "nspk:agent:other-01:v1" });
    expect(() => s.keys.revoke("nspk:agent:other-01:v1", key.kid)).toThrow(KeyNotFoundError);
    expect(() => s.keys.revoke(CODE, "no-such-kid")).toThrow(KeyNotFoundError);
    expect(s.keys.lookup(CODE, key.kid)?.status).toBe("ACTIVE");
  });

  it("конкурентный отзыв по устаревшей версии строки — не проходит", () => {
    const s = stand();
    const key = s.admit();
    expect(s.store.revokeKey(key.kid, key.row_version + 1, "x")).toBeUndefined();
    expect(s.store.revokeKey(key.kid, key.row_version, NOW.toISOString())).toMatchObject({ row_version: 2 });
    expect(s.store.revokeKey(key.kid, 2, "y")?.revoked_at).toBeUndefined();
  });
});

describe("поиск ключа для проверки подписи (РП23 п. 3)", () => {
  it("только среди ключей агента: kid чужого агента — как неизвестный", () => {
    const s = stand();
    const a = s.admit();
    const b = s.admit({ agent_code: "nspk:agent:other-01:v1" });
    expect(s.keys.lookup(CODE, b.kid)).toBeUndefined();
    expect(s.keys.lookup("nspk:agent:other-01:v1", a.kid)).toBeUndefined();
    expect(s.keys.lookup("nspk:agent:nobody:v1", a.kid)).toBeUndefined();
    expect(s.keys.lookup(CODE, a.kid)?.publicKey).toBe(a.public_key);
  });

  it("ключи в хранилище не меняются снаружи", () => {
    const s = stand();
    const key = s.admit();
    expect(() => {
      (s.store.getKey(key.kid) as { revoked_at: string | null }).revoked_at = null;
    }).toThrow(TypeError);
  });

  it("статусы ключа совпадают с ПАО", () => {
    expect(KEY_STATUSES_MATCH_PAO).toBe(true);
  });
});
