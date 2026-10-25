import { readFileSync } from "node:fs";
import {
  AsyncMemoryNonceStore,
  newEd25519Signer,
  signRequest,
  type AsyncNonceStore,
  type HttpLike,
  type Signer,
} from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  PAO_NONCE_SCOPE,
  PaoRequestVerifier,
  nonceRetainMs,
  nonceValue,
  paoError,
  paoNonceStore,
  startNoncePurge,
  type PaoAuthResult,
  type PaoAuthSources,
  type PaoRequest,
} from "../../src/pao/index.js";
import {
  AgentKeys,
  AgentRegistry,
  ED25519,
  InMemoryAgentRegistryStore,
  parseKey,
  type KeyPolicy,
} from "../../src/registry/index.js";
import { PAO_ERRORS } from "../../src/shared/pao-errors.generated.js";

const NOW = new Date("2026-10-11T12:00:00Z");
const SKEW = 300;
const POLICY: KeyPolicy = { key_ttl_days: 90, key_overlap_days: 7 };
const A = "nspk:agent:buyref-01:v3";
const B = "nspk:agent:other-01:v1";

/** Пара ключей агента; kid — отпечаток, который выдаст Платформа (РП23 п. 3), агент вычисляет его сам. */
function agentSigner(): { signer: Signer; publicKey: string } {
  const { signer, publicKey } = newEd25519Signer("tmp");
  const { kid } = parseKey([ED25519], "ed25519", publicKey) as { kid: string };
  return { signer: { ...signer, kid }, publicKey };
}

/** Хранилище ядра в памяти, записывающее значения, которые дошли до seen() (РП30 п. 2). */
type Counting = AsyncNonceStore & { readonly values: string[] };
function counting(): Counting {
  const inner = paoNonceStore({ skewSec: SKEW, now: () => NOW.getTime() });
  const values: string[] = [];
  return {
    values,
    seen: (n) => (values.push(n), inner.seen(n)),
    purge: () => inner.purge(),
  };
}

function stand(nonces?: AsyncNonceStore) {
  let clock = NOW;
  const now = (): Date => clock;
  const store = new InMemoryAgentRegistryStore();
  const registry = new AgentRegistry(store, { keys: POLICY, now });
  const keys = new AgentKeys(store, { keys: POLICY, now });
  const admit = (agent_code: string): Signer => {
    const { signer, publicKey } = agentSigner();
    const d = registry.admit(
      { agent_code, class: "BUYER", model: "m", runtime: "r", alg: "ed25519", public_key: publicKey },
      { contour: "sandbox", operator: "op" },
    );
    expect(d.admitted).toBe(true);
    return signer;
  };
  const verifier = new PaoRequestVerifier(
    { getAgent: (c) => registry.get(c), lookupKey: (c, kid) => keys.lookup(c, kid) },
    { skewSec: SKEW, now, ...(nonces ? { nonces } : {}) },
  );
  return { registry, keys, verifier, admit, setClock: (d: Date) => (clock = d) };
}

let nonceSeq = 0;
/** Подписанное обращение так, как его подписывает клиент core: тело без тела — "" (РП16). */
function signed(
  signer: Signer,
  agent_code: string,
  over: { method?: string; path?: string; query?: string; body?: string; nonce?: string; ts?: Date } = {},
): PaoRequest {
  const req: HttpLike = {
    method: over.method ?? "GET",
    path: over.path ?? "/pao/v1/agent",
    query: over.query ?? "",
    headers: {
      "x-agent-code": agent_code,
      "x-timestamp": (over.ts ?? NOW).toISOString(),
      "x-nonce": over.nonce ?? `n-${++nonceSeq}`,
    },
    body: over.body ?? "",
  };
  const s = signRequest(req, signer);
  return { method: s.method, path: s.path, query: s.query ?? "", headers: s.headers, body: s.body ?? "" };
}

const without = (req: PaoRequest, name: string): PaoRequest => ({
  ...req,
  headers: Object.fromEntries(Object.entries(req.headers).filter(([k]) => k !== name)),
});

const code = (r: PaoAuthResult): string => (r.ok ? "OK" : r.code);

describe("проверка обращения ПАО: принято (ПАО §2)", () => {
  it("GET без тела: content-digest от пустого тела; агент — из реестра, kid — его ключ", async () => {
    const s = stand();
    const signer = s.admit(A);
    const r = await s.verifier.verify(signed(signer, A));
    expect(r).toMatchObject({ ok: true, kid: signer.kid, agent: { agent_code: A, class: "BUYER", level: 1 } });
  });

  it("POST с телом и запросом", async () => {
    const s = stand();
    const signer = s.admit(A);
    const req = signed(signer, A, { method: "POST", path: "/pao/v1/mandates", query: "a=1", body: '{"x":1}' });
    expect(code(await s.verifier.verify(req))).toBe("OK");
  });

  it("регистр имён заголовков не важен", async () => {
    const s = stand();
    const signer = s.admit(A);
    const req = signed(signer, A);
    const upper = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toUpperCase(), v]));
    expect(code(await s.verifier.verify({ ...req, headers: upper }))).toBe("OK");
  });
});

describe("ключ — только среди ключей агента из x-agent-code (РП23 п. 3, инвариант 5)", () => {
  it("агент A подписывает своим ключом от имени B — SIGNATURE_INVALID", async () => {
    const s = stand();
    const a = s.admit(A);
    s.admit(B);
    expect(code(await s.verifier.verify(signed(a, B)))).toBe("SIGNATURE_INVALID");
  });

  it("ключ B под кодом A с подменой keyid — SIGNATURE_INVALID", async () => {
    const s = stand();
    const a = s.admit(A);
    const b = s.admit(B);
    const req = signed(a, A);
    const input = (req.headers["signature-input"] as string).replace(a.kid, b.kid);
    expect(code(await s.verifier.verify({ ...req, headers: { ...req.headers, "signature-input": input } }))).toBe(
      "SIGNATURE_INVALID",
    );
  });

  it("неизвестный у агента kid — SIGNATURE_INVALID (РП23 п. 6.2)", async () => {
    const s = stand();
    s.admit(A);
    const { signer } = agentSigner();
    expect(code(await s.verifier.verify(signed(signer, A)))).toBe("SIGNATURE_INVALID");
  });
});

describe("порядок проверки и коды (РП23 п. 6)", () => {
  it("нет x-agent-code или агента нет в реестре — AGENT_UNKNOWN, раньше подписи", async () => {
    const s = stand();
    const signer = s.admit(A);
    const req = signed(signer, A);
    expect(await s.verifier.verify(without(req, "x-agent-code"))).toEqual({
      ok: false,
      code: "AGENT_UNKNOWN",
      norm: "A2 п. 5.1",
    });
    expect(code(await s.verifier.verify(signed(signer, "nspk:agent:nobody:v1")))).toBe("AGENT_UNKNOWN");
    expect(code(await s.verifier.verify({ ...req, headers: { ...req.headers, "x-agent-code": "" } }))).toBe("AGENT_UNKNOWN");
  });

  it("отозванный ключ — AGENT_KEY_REVOKED на следующей же проверке", async () => {
    const s = stand();
    const signer = s.admit(A);
    expect(code(await s.verifier.verify(signed(signer, A)))).toBe("OK");
    s.keys.revoke(A, signer.kid);
    expect(await s.verifier.verify(signed(signer, A))).toEqual({ ok: false, code: "AGENT_KEY_REVOKED", norm: "A2 п. 5.4" });
  });

  it("истёкший ключ — AGENT_KEY_REVOKED (отдельного кода в ПАО нет)", async () => {
    const s = stand();
    const signer = s.admit(A);
    const later = new Date(NOW.getTime() + 90 * 86_400_000);
    s.setClock(later);
    expect(code(await s.verifier.verify(signed(signer, A, { ts: later })))).toBe("AGENT_KEY_REVOKED");
  });

  it("после отзыва новый ключ работает, старый — нет", async () => {
    const s = stand();
    const old = s.admit(A);
    const next = agentSigner();
    s.keys.register(A, { alg: "ed25519", public_key: next.publicKey });
    s.keys.revoke(A, old.kid);
    expect(code(await s.verifier.verify(signed(next.signer, A)))).toBe("OK");
    expect(code(await s.verifier.verify(signed(old, A)))).toBe("AGENT_KEY_REVOKED");
  });

  it.each(["SUSPENDED", "EXCLUDED"] as const)("%s: изменяющий и прочие методы — AGENT_SUSPENDED", async (to) => {
    const s = stand();
    const signer = s.admit(A);
    s.registry.changeStatus(A, { to, ground: "KEY_COMPROMISE" });
    const post = signed(signer, A, { method: "POST", path: "/pao/v1/mandates", body: "{}" });
    expect(await s.verifier.verify(post)).toEqual({ ok: false, code: "AGENT_SUSPENDED", norm: "A2 п. 7.1" });
    expect(code(await s.verifier.verify(signed(signer, A, { path: "/pao/v1/mandates/m-1" })))).toBe("AGENT_SUSPENDED");
    expect(code(await s.verifier.verify(signed(signer, A, { path: "/pao/v1/agent/" })))).toBe("AGENT_SUSPENDED");
    expect(code(await s.verifier.verify(signed(signer, A, { method: "POST", body: "{}" })))).toBe("AGENT_SUSPENDED");
  });

  it("SUSPENDED: POST relinquish доступен (#33), EXCLUDED — AGENT_SUSPENDED; похожие пути и методы — AGENT_SUSPENDED", async () => {
    const path = "/pao/v1/mandates/mnd_00000000-0000-4000-8000-000000000000/relinquish";
    for (const to of ["SUSPENDED", "EXCLUDED"] as const) {
      const s = stand();
      const signer = s.admit(A);
      s.registry.changeStatus(A, { to, ground: "KEY_COMPROMISE" });
      const res = await s.verifier.verify(signed(signer, A, { method: "POST", path, body: "" }));
      expect([to, code(res)]).toEqual([to, to === "SUSPENDED" ? "OK" : "AGENT_SUSPENDED"]);
      if (to === "SUSPENDED") {
        expect(code(await s.verifier.verify(signed(signer, A, { method: "POST", path: `${path}/`, body: "" })))).toBe("AGENT_SUSPENDED");
        expect(code(await s.verifier.verify(signed(signer, A, { path })))).toBe("AGENT_SUSPENDED");
        expect(code(await s.verifier.verify(signed(signer, A, { method: "POST", path: "/pao/v1/mandates/a/b/relinquish", body: "" })))).toBe("AGENT_SUSPENDED");
      }
    }
  });

  it("SUSPENDED: POST отзыв своего ключа доступен (РП60 п. 3), EXCLUDED — AGENT_SUSPENDED; похожие пути и методы — AGENT_SUSPENDED", async () => {
    for (const to of ["SUSPENDED", "EXCLUDED"] as const) {
      const s = stand();
      const signer = s.admit(A);
      s.registry.changeStatus(A, { to, ground: "KEY_COMPROMISE" });
      const path = `/pao/v1/agent/keys/${signer.kid}/revoke`;
      const res = await s.verifier.verify(signed(signer, A, { method: "POST", path, body: "" }));
      expect([to, code(res)]).toEqual([to, to === "SUSPENDED" ? "OK" : "AGENT_SUSPENDED"]);
      if (to === "SUSPENDED") {
        const denied = [
          signed(signer, A, { method: "POST", path: `${path}/`, body: "" }),
          signed(signer, A, { method: "POST", path: "/pao/v1/agent/keys/a/b/revoke", body: "" }),
          signed(signer, A, { method: "POST", path: "/pao/v1/agent/keys//revoke", body: "" }),
          signed(signer, A, { method: "POST", path: `/x${path}`, body: "" }),
          signed(signer, A, { path }),
          // Регистрация ключа приостановленным — по-прежнему 403 (РП23 доп. 8).
          signed(signer, A, { method: "POST", path: "/pao/v1/agent/keys", body: "{}" }),
        ];
        for (const req of denied) expect([req.method, req.path, code(await s.verifier.verify(req))]).toEqual([req.method, req.path, "AGENT_SUSPENDED"]);
      }
    }
  });

  it.each(["SUSPENDED", "EXCLUDED"] as const)("%s: GET /pao/v1/agent доступен — агент узнаёт свой статус", async (to) => {
    const s = stand();
    const signer = s.admit(A);
    s.registry.changeStatus(A, { to, ground: "KEY_COMPROMISE" });
    expect(await s.verifier.verify(signed(signer, A))).toMatchObject({ ok: true, agent: { status: to } });
  });

  it("приостановленный с неверной подписью — SIGNATURE_INVALID: подпись раньше статуса", async () => {
    const s = stand();
    const signer = s.admit(A);
    s.registry.changeStatus(A, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    const req = signed(signer, A, { method: "POST", path: "/pao/v1/mandates", body: "{}" });
    expect(code(await s.verifier.verify({ ...req, body: "{ }" }))).toBe("SIGNATURE_INVALID");
  });
});

describe("подпись: состав, digest, окно, nonce (ПАО §2)", () => {
  it.each([
    ["тело", { body: '{"x":2}' }],
    ["путь", { path: "/pao/v1/agent/keys" }],
    ["запрос", { query: "a=2" }],
    ["метод", { method: "DELETE" }],
  ])("подмена после подписи — SIGNATURE_INVALID: %s", async (_n, change) => {
    const s = stand();
    const signer = s.admit(A);
    const req = signed(signer, A, { method: "POST", path: "/pao/v1/mandates", query: "a=1", body: '{"x":1}' });
    expect(code(await s.verifier.verify({ ...req, ...change }))).toBe("SIGNATURE_INVALID");
  });

  it("подмена x-agent-code, x-timestamp, x-nonce — подписанные заголовки", async () => {
    const s = stand();
    const signer = s.admit(A);
    s.admit(B);
    for (const [h, v] of [
      ["x-agent-code", B],
      ["x-timestamp", new Date(NOW.getTime() + 1000).toISOString()],
      ["x-nonce", "other"],
    ]) {
      const req = signed(signer, A);
      expect(code(await s.verifier.verify({ ...req, headers: { ...req.headers, [h as string]: v } }))).toBe(
        "SIGNATURE_INVALID",
      );
    }
  });

  it("GET, подписанный без content-digest, — SIGNATURE_INVALID (РП16)", async () => {
    const s = stand();
    const signer = s.admit(A);
    const req = signRequest(
      {
        method: "GET",
        path: "/pao/v1/agent",
        headers: { "x-agent-code": A, "x-timestamp": NOW.toISOString(), "x-nonce": "n-nodigest" },
      },
      signer,
      ["@method", "@path", "@query", "x-agent-code", "x-timestamp", "x-nonce"],
    );
    expect(code(await s.verifier.verify({ method: "GET", path: req.path, query: "", headers: req.headers, body: "" }))).toBe(
      "SIGNATURE_INVALID",
    );
  });

  it("alg в Signature-Input не совпадает с alg ключа — SIGNATURE_INVALID (РП5)", async () => {
    const s = stand();
    const signer = s.admit(A);
    const req = signed(signer, A);
    const input = (req.headers["signature-input"] as string).replace('alg="ed25519"', 'alg="gost3410"');
    expect(code(await s.verifier.verify({ ...req, headers: { ...req.headers, "signature-input": input } }))).toBe(
      "SIGNATURE_INVALID",
    );
  });

  it("окно signature_skew_sec: на границе — принято, за границей в обе стороны — SIGNATURE_INVALID", async () => {
    const s = stand();
    const signer = s.admit(A);
    const shift = (sec: number): Date => new Date(NOW.getTime() + sec * 1000);
    expect(code(await s.verifier.verify(signed(signer, A, { ts: shift(-SKEW) })))).toBe("OK");
    expect(code(await s.verifier.verify(signed(signer, A, { ts: shift(SKEW) })))).toBe("OK");
    expect(code(await s.verifier.verify(signed(signer, A, { ts: shift(-SKEW - 1) })))).toBe("SIGNATURE_INVALID");
    expect(code(await s.verifier.verify(signed(signer, A, { ts: shift(SKEW + 1) })))).toBe("SIGNATURE_INVALID");
  });

  it("повтор nonce — SIGNATURE_INVALID; тот же nonce у другого агента — принят", async () => {
    const s = stand();
    const a = s.admit(A);
    const b = s.admit(B);
    expect(code(await s.verifier.verify(signed(a, A, { nonce: "same" })))).toBe("OK");
    expect(code(await s.verifier.verify(signed(a, A, { nonce: "same" })))).toBe("SIGNATURE_INVALID");
    expect(code(await s.verifier.verify(signed(b, B, { nonce: "same" })))).toBe("OK");
  });

  it("повтор того же обращения целиком — SIGNATURE_INVALID", async () => {
    const s = stand();
    const signer = s.admit(A);
    const req = signed(signer, A);
    expect(code(await s.verifier.verify(req))).toBe("OK");
    expect(code(await s.verifier.verify(req))).toBe("SIGNATURE_INVALID");
  });

  it("неподписанный запрос не занимает nonce: nonce запоминается только после успешной проверки", async () => {
    const s = stand(counting());
    const signer = s.admit(A);
    const req = signed(signer, A, { nonce: "victim" });
    expect(code(await s.verifier.verify({ ...req, headers: { ...req.headers, signature: "sig1=:AAAA:" } }))).toBe(
      "SIGNATURE_INVALID",
    );
    expect(code(await s.verifier.verify(signed(signer, A, { nonce: "victim", body: "" })))).toBe("OK");
    expect((s.verifier.nonces as Counting).values).toEqual([`${A} victim`]);
  });

  it("отклонённый по статусу запрос nonce занимает: подпись была верной", async () => {
    const s = stand();
    const signer = s.admit(A);
    s.registry.changeStatus(A, { to: "SUSPENDED", ground: "KEY_COMPROMISE" });
    const req = signed(signer, A, { method: "POST", path: "/pao/v1/mandates", body: "{}", nonce: "n-s" });
    expect(code(await s.verifier.verify(req))).toBe("AGENT_SUSPENDED");
    expect(code(await s.verifier.verify(req))).toBe("SIGNATURE_INVALID");
  });

  it("пустой или отсутствующий nonce — SIGNATURE_INVALID", async () => {
    const s = stand();
    const signer = s.admit(A);
    expect(code(await s.verifier.verify(signed(signer, A, { nonce: "" })))).toBe("SIGNATURE_INVALID");
    const req = signed(signer, A);
    expect(code(await s.verifier.verify(without(req, "x-nonce")))).toBe("SIGNATURE_INVALID");
  });

  it("повторённый заголовок (массив значений) — SIGNATURE_INVALID, не догадка", async () => {
    const s = stand();
    const signer = s.admit(A);
    const req = signed(signer, A);
    expect(code(await s.verifier.verify({ ...req, headers: { ...req.headers, "x-nonce": ["a", "b"] } }))).toBe(
      "SIGNATURE_INVALID",
    );
  });

  it("сбой реестра или ключей — 503 UPSTREAM_UNAVAILABLE, не ошибка агента и не исключение (аудит PS-04 №2)", async () => {
    const s = stand();
    const signer = s.admit(A);
    const down = (): never => {
      throw new Error("db down");
    };
    const verifierWith = (sources: Partial<PaoAuthSources>) =>
      new PaoRequestVerifier(
        {
          getAgent: (c) => s.registry.get(c),
          lookupKey: (c, kid) => s.keys.lookup(c, kid),
          ...sources,
        },
        { skewSec: SKEW, now: () => NOW },
      );
    const r1 = await verifierWith({ lookupKey: down }).verify(signed(signer, A));
    const r2 = await verifierWith({ getAgent: down }).verify(signed(signer, A));
    for (const r of [r1, r2]) {
      expect(r).toMatchObject({ ok: false, code: "UPSTREAM_UNAVAILABLE" });
      expect((r as { cause?: Error }).cause?.message).toBe("db down");
    }
    expect(paoError("UPSTREAM_UNAVAILABLE").http).toBe(503);
    expect(paoError("UPSTREAM_UNAVAILABLE").body.retry).toBe("same_key");
  });

  it("исключение не из источника (проверка подписи) — SIGNATURE_INVALID, не UPSTREAM (повторный аудит №2)", async () => {
    const s = stand();
    const signer = s.admit(A);
    const v = new PaoRequestVerifier(
      { getAgent: (c) => s.registry.get(c), lookupKey: (c, kid) => s.keys.lookup(c, kid) },
      {
        skewSec: SKEW,
        now: () => NOW,
        verifier: {
          verify: () => {
            throw new Error("сбой криптографии");
          },
        },
      },
    );
    const r = await v.verify(signed(signer, A));
    expect(r).toEqual({ ok: false, code: "SIGNATURE_INVALID", norm: "A2 п. 5.1" });
  });

  it("сбой источника не занимает nonce: повтор после восстановления принимается", async () => {
    const s = stand();
    const signer = s.admit(A);
    let up = false;
    const v = new PaoRequestVerifier(
      {
        getAgent: (c) => s.registry.get(c),
        lookupKey: (c, kid) => {
          if (!up) throw new Error("db down");
          return s.keys.lookup(c, kid);
        },
      },
      { skewSec: SKEW, now: () => NOW },
    );
    const req = signed(signer, A);
    expect(code(await v.verify(req))).toBe("UPSTREAM_UNAVAILABLE");
    up = true;
    expect(code(await v.verify(req))).toBe("OK");
  });
});

describe("хранилище nonce", () => {
  it("срок хранения — ровно 2 × signature_skew_sec; меньший ядро отвергает (РП23 п. 6, РП30 п. 2)", async () => {
    expect(nonceRetainMs(SKEW)).toBe(2 * SKEW * 1000);
    expect(() => new AsyncMemoryNonceStore({ retainMs: nonceRetainMs(SKEW) - 1, skewSec: SKEW })).toThrow(RangeError);
    let t = NOW.getTime();
    const n = paoNonceStore({ skewSec: SKEW, now: () => t });
    expect(await n.seen(`${A} x`)).toBe(false);
    t += 2 * SKEW * 1000;
    expect(await n.purge()).toBe(0);
    expect(await n.seen(`${A} x`)).toBe(true);
    t += 1;
    expect(await n.purge()).toBe(1);
  });

  it("окно — ещё раз по свежим часам после записи nonce: край окна, ушедший за время записи, — отказ (аудит К2.3 №2)", async () => {
    let clock = NOW;
    const inner = paoNonceStore({ skewSec: SKEW, now: () => clock.getTime() });
    // Запись nonce «занимает» 1 мс: за это время метка обращения выходит из окна.
    const slow: AsyncNonceStore = {
      seen: async (n) => {
        const r = await inner.seen(n);
        clock = new Date(clock.getTime() + 1);
        return r;
      },
      purge: () => inner.purge(),
    };
    const s = stand(slow);
    const signer = s.admit(A);
    s.setClock(NOW);
    const v = new PaoRequestVerifier(
      { getAgent: (c) => s.registry.get(c), lookupKey: (c, kid) => s.keys.lookup(c, kid) },
      { skewSec: SKEW, now: () => clock, nonces: slow },
    );
    const edge = signed(signer, A, { ts: new Date(NOW.getTime() - SKEW * 1000) });
    expect(code(await v.verify(edge))).toBe("SIGNATURE_INVALID");
    const inside = signed(signer, A, { ts: new Date(NOW.getTime() - SKEW * 1000 + 10) });
    expect(code(await v.verify(inside))).toBe("OK");
  });

  it("остановка очистки дожидается идущей purge(): ложного сбоя после закрытия пула нет (аудит К2.3 №5)", async () => {
    let release!: () => void;
    let purges = 0;
    const errors: unknown[] = [];
    const store: AsyncNonceStore = {
      seen: async () => false,
      purge: () =>
        new Promise<number>((r) => {
          purges++;
          release = () => r(0);
        }),
    };
    const stop = startNoncePurge(store, 5, (e) => errors.push(e));
    await new Promise((r) => setTimeout(r, 20));
    expect(purges).toBeGreaterThan(0);
    let stopped = false;
    const done = stop().then(() => (stopped = true));
    await new Promise((r) => setTimeout(r, 10));
    expect(stopped).toBe(false);
    release();
    await done;
    expect(stopped).toBe(true);
    expect(errors).toEqual([]);
  });

  it("значение — код агента, пробел, x-nonce: разбор по первому пробелу однозначен (РП30 п. 2)", () => {
    expect(nonceValue(A, "a b:c")).toBe(`${A} a b:c`);
    // При «:» склейки двух допустимых кодов совпали бы; с пробелом — нет.
    expect(nonceValue("nspk:agent:id:v1", "z:v3:q")).not.toBe(nonceValue("nspk:agent:id:v1:z:v3", "q"));
    expect(PAO_NONCE_SCOPE).toBe("pao");
  });

  it("по умолчанию ttl = 2 × signature_skew_sec: повтор в пределах окна времени ловится всегда", async () => {
    const s = stand();
    const signer = s.admit(A);
    // Метка на верхней границе окна: обращение годно до NOW + 2 × SKEW по часам Платформы.
    const ts = new Date(NOW.getTime() + SKEW * 1000);
    const req = signed(signer, A, { ts });
    expect(code(await s.verifier.verify(req))).toBe("OK");
    for (const ms of [2 * SKEW * 1000 - 1, 2 * SKEW * 1000]) {
      s.setClock(new Date(NOW.getTime() + ms));
      expect(code(await s.verifier.verify(req)), `+${ms} мс`).toBe("SIGNATURE_INVALID");
    }
    // Дальше обращение вне окна времени: повтор закрыт окном, а не памятью nonce.
    s.setClock(new Date(NOW.getTime() + 2 * SKEW * 1000 + 1));
    expect(code(await s.verifier.verify(req))).toBe("SIGNATURE_INVALID");
  });
});

describe("тело ошибки — строго ПАО §6 (РП23 п. 7)", () => {
  const schema = (
    parse(readFileSync("docs/core/agent-protocol.yaml", "utf8")) as {
      components: { schemas: { Error: { properties: Record<string, unknown>; required: string[] } } };
    }
  ).components.schemas.Error;

  it.each(PAO_ERRORS.map((e) => [e.code, e] as const))("%s: HTTP и retry — из x-pao-errors", async (c, spec) => {
    const r = paoError(c, "A2 п. 5.1");
    expect(r.http).toBe(spec.http);
    expect(r.body).toEqual({ code: c, message: spec.description, norm: "A2 п. 5.1", retry: spec.retry });
  });

  it("поля — только из схемы Error, обязательные есть; без norm — без поля", async () => {
    const body = paoError("SIGNATURE_INVALID").body;
    for (const k of schema.required) expect(body).toHaveProperty(k);
    expect(Object.keys(body).every((k) => Object.hasOwn(schema.properties, k))).toBe(true);
    expect(Object.keys(paoError("AGENT_UNKNOWN", "A2").body).sort()).toEqual(["code", "message", "norm", "retry"]);
    expect(body).not.toHaveProperty("norm");
  });

  it("код вне таблицы — исключение", async () => {
    expect(() => paoError("NOPE" as "AGENT_UNKNOWN")).toThrow();
  });
});
