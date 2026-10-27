import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
  const admit = async (over: Record<string, unknown> = {}): Promise<AgentKey> => {
    const d = await registry.admit(application(over), { contour: "sandbox", operator: OPERATOR });
    expect(d).toMatchObject({ admitted: true });
    return (d as { key: AgentKey }).key;
  };
  return { store, registry, keys, admit, setClock: (d: Date) => (clock = d) };
}

/** Хранилище-обёртка: все методы делегируются, кроме подменённых (гонка между чтением и записью). */
const wrap = (store: AgentRegistryStore, over: Partial<AgentRegistryStore>): AgentRegistryStore => ({
  get: (c) => store.get(c),
  agentCodes: () => store.agentCodes(),
  catalogKeys: (ct) => store.catalogKeys(ct),
  ownerOf: (i, id) => store.ownerOf(i, id),
  insert: (r, k) => store.insert(r, k),
  updateStatus: (c, v, f) => store.updateStatus(c, v, f),
  getKey: (kid) => store.getKey(kid),
  keysOf: (c) => store.keysOf(c),
  addKey: (k, e, sh, v) => store.addKey(k, e, sh, v),
  revokeKey: (kid, v, at) => store.revokeKey(kid, v, at),
  subscriptionOf: (c) => store.subscriptionOf(c),
  setSubscription: (c, s) => store.setSubscription(c, s),
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

  it("допуск с эталонным ключом выдаёт эталонный kid", async () => {
    expect((await stand().admit({ public_key: RFC8037_SPKI })).kid).toBe(RFC8037_KID);
  });

  it.each([
    ["base64url вместо base64", RFC8037_SPKI.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") + "_"],
    ["без дополнения", RFC8037_SPKI.replace(/=+$/, "")],
    ["с пробелом", ` ${RFC8037_SPKI}`],
    ["с переводом строки", `${RFC8037_SPKI.slice(0, 20)}\n${RFC8037_SPKI.slice(20)}`],
    ["ключ X25519", newPublicKey("x25519")],
    ["32 байта без SPKI", Buffer.from(RFC8037_X, "base64url").toString("base64")],
    ["лишний байт после DER", Buffer.concat([Buffer.from(RFC8037_SPKI, "base64"), Buffer.from([0])]).toString("base64")],
    // RFC 4648 §3.5: «…URo=» и «…URp=» — те же байты; каноническая — с нулевыми лишними битами (агент, расхождение № 8).
    ["лишние биты перед «=»", RFC8037_SPKI.replace(/o=$/, "p=")],
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
  // Неканоническая запись: нейтраль и −1 со знаковым битом при x = 0; y = p + 1, y = p и y = p + 3.
  // y = p + 1 и y = p по модулю p — точки малого порядка; y = p + 3 — нет, его ловит только проверка y < p.
  const Y_P_PLUS_3 = "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
  const NON_CANONICAL = [
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    Y_P_PLUS_3,
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
    expect(parseKey([ED25519], "ed25519", spkiOf(hex))).toBeNull();
  });

  it("y = p + 3 — запись точки большого порядка: каноническая (y = 3) не слабая", () => {
    expect(isWeakEd25519(Buffer.from(`03${"00".repeat(31)}`, "hex"))).toBe(false);
  });

  it("допуск с лишними битами base64 — KEY_INVALID, ничего не сохранено; канонический — тот же kid", async () => {
    const s = stand();
    const noncanonical = RFC8037_SPKI.replace(/o=$/, "p=");
    expect(Buffer.from(noncanonical, "base64").equals(Buffer.from(RFC8037_SPKI, "base64"))).toBe(true);
    const d = await s.registry.admit(application({ public_key: noncanonical }), { contour: "sandbox", operator: OPERATOR });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(await s.store.get(CODE)).toBeUndefined();
    expect((await s.admit({ public_key: RFC8037_SPKI })).kid).toBe(RFC8037_KID);
    await expect(s.keys.register(CODE, { alg: "ed25519", public_key: noncanonical })).rejects.toThrow(KeyInvalidError);
  });

  it("эталон RFC 8037 и случайные ключи — не слабые", () => {
    expect(isWeakEd25519(Buffer.from(RFC8037_X, "base64url"))).toBe(false);
    for (let i = 0; i < 50; i++) {
      const x = Buffer.from(newPublicKey(), "base64").subarray(12);
      expect(isWeakEd25519(x)).toBe(false);
    }
  });

  it("допуск со слабым ключом — KEY_INVALID, ничего не сохранено; register — KeyInvalidError", async () => {
    const s = stand();
    const d = await s.registry.admit(application({ public_key: spkiOf(SMALL_ORDER[0]!) }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(await s.store.get(CODE)).toBeUndefined();
    await s.admit();
    for (const hex of SMALL_ORDER) {
      await expect(s.keys.register(CODE, { alg: "ed25519", public_key: spkiOf(hex) })).rejects.toThrow(KeyInvalidError);
    }
    expect(await s.keys.list(CODE)).toHaveLength(1);
  });
});

// Векторы ядра — общий источник для платформы, агента и продавцов (agentic-core v0.3.0, К10). Свои векторы выше остаются:
// они независимы от ядра (y = p + 3 у нас — без знакового бита, у агента — со знаковым, ревью PR #29).
describe("слабые ключи Ed25519 — сверка с векторами ed25519_weak_keys ядра (PS-05 К1.2)", () => {
  const vectorsPath = fileURLToPath(new URL("../../vectors/vectors.json", import.meta.resolve("@kuzin4u/agentic-core")));
  const VECTORS = (JSON.parse(readFileSync(vectorsPath, "utf8")) as {
    ed25519_weak_keys: { point: string; weak: boolean; why: string }[];
  }).ed25519_weak_keys;
  const spkiOf = (hex: string): string =>
    Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]).toString("base64");

  it("векторы на месте: есть и слабые, и годные", () => {
    expect(VECTORS.filter((v) => v.weak).length).toBeGreaterThanOrEqual(8);
    expect(VECTORS.some((v) => !v.weak)).toBe(true);
  });

  it.each(VECTORS.map((v) => [v.why, v] as const))("%s", (_why, v) => {
    expect(isWeakEd25519(Buffer.from(v.point, "hex"))).toBe(v.weak);
    // Слабый — KEY_INVALID при разборе (null); годный — разбирается.
    expect(parseKey([ED25519], "ed25519", spkiOf(v.point)) === null).toBe(v.weak);
  });
});

describe("первый ключ при допуске (РП23 п. 2)", () => {
  it("ключ сохраняется вместе с записью: kid, срок key_ttl_days, ACTIVE", async () => {
    const s = stand();
    const key = await s.admit();
    expect(key).toMatchObject({
      agent_code: CODE,
      alg: "ed25519",
      valid_from: NOW.toISOString(),
      valid_to: at(90).toISOString(),
      revoked_at: null,
    });
    expect(await s.keys.list(CODE)).toEqual([
      {
        kid: key.kid,
        alg: "ed25519",
        public_key: key.public_key,
        valid_from: NOW.toISOString(),
        valid_to: at(90).toISOString(),
        status: "ACTIVE",
      },
    ]);
    expect(await s.keys.lookup(CODE, key.kid)).toEqual({ alg: "ed25519", publicKey: key.public_key, status: "ACTIVE" });
  });

  it("ключ, уже зарегистрированный у другого агента, — KEY_INVALID, агент не сохранён", async () => {
    const s = stand();
    const key = await s.admit();
    const other = "nspk:agent:other-01:v1";
    const d = await s.registry.admit(application({ agent_code: other, public_key: key.public_key }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(await s.registry.get(other)).toBeUndefined();
  });

  it.each([
    ["ключ другого агента", (k: AgentKey) => k.public_key],
    ["неразборчивый ключ", () => "AAAA"],
    ["ключ X25519", () => newPublicKey("x25519")],
  ])("KEY_INVALID при допуске (%s): в хранилище нет ни записи, ни владельца, ни ключа", async (_n, pk) => {
    const s = stand();
    const existing = await s.admit();
    const other = "nspk:agent:other-01:v1";
    const publicKey = pk(existing);
    const d = await s.registry.admit(application({ agent_code: other, public_key: publicKey }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(await s.store.get(other)).toBeUndefined();
    expect(await s.store.ownerOf("nspk:agent", "other-01")).toBeUndefined();
    expect(await s.store.keysOf(other)).toEqual([]);
    expect(await s.store.getKey(existing.kid)).toEqual(existing);
    expect(await s.store.keysOf(CODE)).toEqual([existing]);
    const parsed = parseKey([ED25519], "ed25519", publicKey);
    if (parsed && parsed.kid !== existing.kid) expect(await s.store.getKey(parsed.kid)).toBeUndefined();
  });

  it("контур оператора: до точки расширения ГОСТ (РП5) ed25519 не принимается — KEY_INVALID", async () => {
    expect(DEFAULT_KEY_ALGORITHMS.operator).toEqual([]);
    const d = await stand().registry.admit(application({ conformance_run_ref: "RUN-77" }), {
      contour: "operator",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
  });

  it("неделимость в хранилище: kid занят — не сохраняется ни запись, ни ключ", async () => {
    const s = stand();
    const key = await s.admit();
    const d = await stand().registry.admit(application({ agent_code: "nspk:agent:other-01:v1" }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    const rec = (d as { record: Parameters<InMemoryAgentRegistryStore["insert"]>[0] }).record;
    const clash = { ...key, agent_code: rec.agent_code };
    await expect(s.store.insert(rec, clash)).rejects.toThrow(KeyTakenError);
    expect(await s.store.get(rec.agent_code)).toBeUndefined();
    expect(await s.store.ownerOf(rec.issuer, rec.id)).toBeUndefined();
    expect(await s.store.keysOf(rec.agent_code)).toEqual([]);
  });

  it("конкурентная регистрация того же ключа между проверкой и вставкой — KEY_INVALID, а не исключение", async () => {
    const s = stand();
    const pk = newPublicKey();
    const kid = (parseKey([ED25519], "ed25519", pk) as { kid: string }).kid;
    const racing = wrap(s.store, {
      getKey: async () => undefined,
      insert: async (record, firstKey) => {
        const racer = "nspk:agent:racer-01:v1";
        await s.store.insert({ ...record, agent_code: racer, id: "racer-01" }, { ...firstKey, agent_code: racer });
        await s.store.insert(record, firstKey);
      },
    });
    const d = await new AgentRegistry(racing, { keys: POLICY, now: () => NOW }).admit(application({ public_key: pk }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect((await s.store.getKey(kid))?.agent_code).toBe("nspk:agent:racer-01:v1");
    expect(await s.store.get(CODE)).toBeUndefined();
  });
});

describe("регистрация ключа и перекрытие (A2 п. 5.3, РП23 п. 4)", () => {
  it("новый ключ — срок key_ttl_days; прежний сокращается до now + key_overlap_days", async () => {
    const s = stand();
    const first = await s.admit();
    s.setClock(at(30));
    const second = await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect(second.valid_to).toBe(at(120).toISOString());
    expect((await s.store.getKey(first.kid))?.valid_to).toBe(at(37).toISOString());
    expect((await s.keys.list(CODE)).map((k) => k.status)).toEqual(["ACTIVE", "ACTIVE"]);
    s.setClock(new Date(at(37).getTime() - 1));
    expect((await s.keys.lookup(CODE, first.kid))?.status).toBe("ACTIVE");
    s.setClock(at(37));
    expect((await s.keys.lookup(CODE, first.kid))?.status).toBe("EXPIRED");
    expect((await s.keys.lookup(CODE, second.kid))?.status).toBe("ACTIVE");
  });

  it("первый ключ истекает по key_ttl_days на подставленных часах: за 1 мс — ACTIVE, в valid_to — EXPIRED", async () => {
    const s = stand();
    const key = await s.admit();
    s.setClock(new Date(at(90).getTime() - 1));
    expect((await s.keys.lookup(CODE, key.kid))?.status).toBe("ACTIVE");
    s.setClock(at(90));
    expect((await s.keys.lookup(CODE, key.kid))?.status).toBe("EXPIRED");
    expect((await s.keys.list(CODE))[0]?.status).toBe("EXPIRED");
    expect(await s.store.getKey(key.kid)).toEqual(key);
  });

  it("key_overlap_days = 0 — прежний ключ истекает сразу", async () => {
    const s = stand({ key_ttl_days: 90, key_overlap_days: 0 });
    const first = await s.admit();
    await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect((await s.keys.lookup(CODE, first.kid))?.status).toBe("EXPIRED");
  });

  it("срок короче перекрытия не продлевается; отозванный и истёкший не трогаются", async () => {
    const s = stand();
    const first = await s.admit();
    s.setClock(at(86));
    const second = await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect((await s.store.getKey(first.kid))?.valid_to).toBe(at(90).toISOString());
    await s.keys.revoke(CODE, second.kid);
    s.setClock(at(91));
    const revokedBefore = await s.store.getKey(second.kid);
    await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    expect((await s.store.getKey(first.kid))?.valid_to).toBe(at(90).toISOString());
    expect(await s.store.getKey(second.kid)).toEqual(revokedBefore);
  });

  it("свой действующий ключ повторно — тот же ключ без изменений (РП23 доп. 7)", async () => {
    const s = stand();
    const first = await s.admit();
    s.setClock(at(10));
    const second = await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    s.setClock(at(12)); // первый ключ ещё действует: перекрытие сократило его до at(17)
    const before = await s.keys.list(CODE);
    expect(await s.keys.register(CODE, { alg: "ed25519", public_key: second.public_key })).toEqual(second);
    expect(await s.keys.register(CODE, { alg: "ed25519", public_key: first.public_key })).toEqual(await s.store.getKey(first.kid));
    expect(await s.keys.list(CODE)).toEqual(before);
  });

  it("свой истёкший ключ повторно — KeyInvalidError TAKEN: истёкший действующим не возвращается", async () => {
    const s = stand();
    const first = await s.admit();
    s.setClock(at(91));
    expect((await s.keys.lookup(CODE, first.kid))?.status).toBe("EXPIRED");
    await expect(s.keys.register(CODE, { alg: "ed25519", public_key: first.public_key })).rejects.toThrow(
      expect.objectContaining({ reason: "TAKEN" }),
    );
  });

  it.each([["неразборчивый", () => "AAAA"]])("неверный ключ — KeyInvalidError: %s", async (_n, pk) => {
    const s = stand();
    await s.admit();
    await expect(s.keys.register(CODE, { alg: "ed25519", public_key: pk() })).rejects.toThrow(KeyInvalidError);
    await expect(s.keys.register(CODE, { alg: "rsa", public_key: newPublicKey() })).rejects.toThrow(KeyInvalidError);
    await expect(s.keys.register(CODE, null)).rejects.toThrow(KeyInvalidError);
    expect(await s.keys.list(CODE)).toHaveLength(1);
  });

  it("отозванный ключ повторно не регистрируется: kid не возвращается (РП23 п. 5)", async () => {
    const s = stand();
    const first = await s.admit();
    await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    await s.keys.revoke(CODE, first.kid);
    await expect(s.keys.register(CODE, { alg: "ed25519", public_key: first.public_key })).rejects.toThrow(KeyInvalidError);
    expect((await s.keys.lookup(CODE, first.kid))?.status).toBe("REVOKED");
  });

  it("отозванный ключ не регистрируется другому агенту — ни через register, ни через допуск", async () => {
    const s = stand();
    const first = await s.admit();
    await s.keys.revoke(CODE, first.kid);
    const other = "nspk:agent:other-01:v1";
    await s.admit({ agent_code: other });
    await expect(s.keys.register(other, { alg: "ed25519", public_key: first.public_key })).rejects.toThrow(KeyInvalidError);
    const third = "nspk:agent:third-01:v1";
    const d = await s.registry.admit(application({ agent_code: third, public_key: first.public_key }), {
      contour: "sandbox",
      operator: OPERATOR,
    });
    expect(reasons(d)).toEqual(["KEY_INVALID"]);
    expect(await s.store.get(third)).toBeUndefined();
    expect(await s.store.getKey(first.kid)).toMatchObject({ agent_code: CODE, revoked_at: NOW.toISOString() });
    expect(await s.keys.lookup(other, first.kid)).toBeUndefined();
  });

  it("ключ другого агента — KeyInvalidError", async () => {
    const s = stand();
    const first = await s.admit();
    await s.admit({ agent_code: "nspk:agent:other-01:v1" });
    await expect(
      s.keys.register("nspk:agent:other-01:v1", { alg: "ed25519", public_key: first.public_key }),
    ).rejects.toThrow(KeyInvalidError);
  });

  it("агента нет — AgentNotFoundError; исключён — AgentExcludedError; приостановлен — можно", async () => {
    const s = stand();
    await expect(s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).rejects.toThrow(AgentNotFoundError);
    await s.admit();
    await s.registry.changeStatus(CODE, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    expect((await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).agent_code).toBe(CODE);
    await s.registry.changeStatus(CODE, { to: "EXCLUDED", ground: "KEY_COMPROMISE" });
    await expect(s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).rejects.toThrow(AgentExcludedError);
  });

  it("конкурентная регистрация: набор ключей агента изменился после чтения — ни один ключ не добавлен", async () => {
    const s = stand();
    const first = await s.admit();
    const expected = new Map([[first.kid, first.row_version]]);
    await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
    const pk = parseKey([ED25519], "ed25519", newPublicKey()) as { kid: string; alg: string; public_key: string };
    const late: AgentKey = { ...first, ...pk, row_version: 1 };
    expect(await s.store.addKey(late, expected, new Map(), 1)).toBe(false);
    expect(await s.store.getKey(pk.kid)).toBeUndefined();
    expect(await s.keys.list(CODE)).toHaveLength(2);
  });

  it("конкурентная регистрация через сервис — ConcurrentChangeError", async () => {
    const s = stand();
    await s.admit();
    const racing = wrap(s.store, {
      addKey: async (key, expected, shorten, v) => {
        await s.keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() });
        return s.store.addKey(key, expected, shorten, v);
      },
    });
    const keys = new AgentKeys(racing, { keys: POLICY, now: () => NOW });
    await expect(keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).rejects.toThrow(ConcurrentChangeError);
    expect(await s.keys.list(CODE)).toHaveLength(2);
  });

  it("исключение агента между проверкой статуса и вставкой — ключ не добавлен (РП23, дополнения; аудит №11)", async () => {
    const s = stand();
    await s.admit();
    const racing = wrap(s.store, {
      addKey: async (key, expected, shorten, v) => {
        await s.registry.changeStatus(CODE, { to: "EXCLUDED", ground: "WITHDRAWN" });
        return s.store.addKey(key, expected, shorten, v);
      },
    });
    const keys = new AgentKeys(racing, { keys: POLICY, now: () => NOW });
    await expect(keys.register(CODE, { alg: "ed25519", public_key: newPublicKey() })).rejects.toThrow(ConcurrentChangeError);
    expect(await s.keys.list(CODE)).toHaveLength(1);
    expect((await s.registry.get(CODE))?.status).toBe("EXCLUDED");
  });
});

describe("отзыв ключа (A2 п. 5.4, РП23 п. 5)", () => {
  it("отзыв действует сразу: статус REVOKED на следующей проверке; повторный отзыв — тот же ключ", async () => {
    const s = stand();
    const key = await s.admit();
    s.setClock(at(1));
    const revoked = await s.keys.revoke(CODE, key.kid);
    expect(revoked).toMatchObject({ kid: key.kid, revoked_at: at(1).toISOString() });
    expect((await s.keys.lookup(CODE, key.kid))?.status).toBe("REVOKED");
    s.setClock(at(2));
    expect(await s.keys.revoke(CODE, key.kid)).toEqual(revoked);
  });

  it("можно отозвать последний действующий ключ", async () => {
    const s = stand();
    const key = await s.admit();
    await s.keys.revoke(CODE, key.kid);
    expect((await s.keys.list(CODE)).filter((k) => k.status === "ACTIVE")).toEqual([]);
  });

  it("отзыв истёкшего ключа — REVOKED", async () => {
    const s = stand();
    const key = await s.admit();
    s.setClock(at(91));
    expect((await s.keys.lookup(CODE, key.kid))?.status).toBe("EXPIRED");
    await s.keys.revoke(CODE, key.kid);
    expect((await s.keys.lookup(CODE, key.kid))?.status).toBe("REVOKED");
  });

  it("чужой kid — KeyNotFoundError, ключ другого агента не отзывается", async () => {
    const s = stand();
    const key = await s.admit();
    await s.admit({ agent_code: "nspk:agent:other-01:v1" });
    await expect(s.keys.revoke("nspk:agent:other-01:v1", key.kid)).rejects.toThrow(KeyNotFoundError);
    await expect(s.keys.revoke(CODE, "no-such-kid")).rejects.toThrow(KeyNotFoundError);
    expect((await s.keys.lookup(CODE, key.kid))?.status).toBe("ACTIVE");
  });

  it("конкурентный отзыв по устаревшей версии строки — не проходит", async () => {
    const s = stand();
    const key = await s.admit();
    expect(await s.store.revokeKey(key.kid, key.row_version + 1, "x")).toBeUndefined();
    expect(await s.store.revokeKey(key.kid, key.row_version, NOW.toISOString())).toMatchObject({ row_version: 2 });
    expect((await s.store.revokeKey(key.kid, 2, "y"))?.revoked_at).toBeUndefined();
  });
});

describe("поиск ключа для проверки подписи (РП23 п. 3)", () => {
  it("только среди ключей агента: kid чужого агента — как неизвестный", async () => {
    const s = stand();
    const a = await s.admit();
    const b = await s.admit({ agent_code: "nspk:agent:other-01:v1" });
    expect(await s.keys.lookup(CODE, b.kid)).toBeUndefined();
    expect(await s.keys.lookup("nspk:agent:other-01:v1", a.kid)).toBeUndefined();
    expect(await s.keys.lookup("nspk:agent:nobody:v1", a.kid)).toBeUndefined();
    expect((await s.keys.lookup(CODE, a.kid))?.publicKey).toBe(a.public_key);
  });

  it("ключи в хранилище не меняются снаружи", async () => {
    const s = stand();
    const key = await s.admit();
    const stored = (await s.store.getKey(key.kid)) as { revoked_at: string | null };
    expect(() => {
      stored.revoked_at = null;
    }).toThrow(TypeError);
  });

  it("статусы ключа совпадают с ПАО", () => {
    expect(KEY_STATUSES_MATCH_PAO).toBe(true);
  });
});
