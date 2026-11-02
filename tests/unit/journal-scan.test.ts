// Сканер журналов (SECURITY Ж4, SPEC §11 п. 7; SEC-2 ч. 2, К3 сессии 66): на стенде проходит путь с настоящими значениями —
// допуск, INTENT и CART с подписью банка, реквизит (POST и GET), авторизация через ADP с криптограммой, ответ эмитента,
// представление, возврат. Затем три журнала — процесса (pino), согласий (выписка evidence) и обращений стенда
// (stand.calls()) — и весь побочный вывод (console.*, process.stdout / stderr) проверяются: номера карты по Луну нет,
// выданной криптограммы нет, закрытого ключа агента и значений его подписей нет — сравнением с фактически использованными
// в прогоне значениями, а не только по шаблону. Сначала — положительный контроль: путь реально прошёл, журналы не пусты.
// Остаточный риск (SECURITY Ж4): сканер ловит известные шаблоны и значения; новое поле с сырым значением другого вида —
// нет (белый список имён полей — PS-33).
import { generateKeyPairSync, randomUUID, sign as cSign } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { CanonicalMessage, Decision } from "../../src/shared/canonical.generated.js";
import type { ServerOptions } from "../../src/server.js";
import { hasPaymentDetails } from "../../src/pao/body.js";
import { createStand, type Stand } from "../../src/stand/index.js";
import { agentKid, buyerApplication, type AgentSide } from "../support/agent.js";
import { letters, opaquePrincipalRef } from "../support/opaque.js";
import { signedInject } from "../support/signed-inject.js";
import { standPay } from "../support/stand-pay.js";
import { calls, LOG_CALL, srcFiles } from "../support/log-calls.js";

const sink = vi.hoisted(() => ({ lines: [] as string[] }));

vi.mock("../../src/server.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/server.js")>();
  return {
    ...actual,
    buildServer: (opts: ServerOptions) =>
      actual.buildServer({ ...opts, logger: { level: "info", stream: { write: (l: string) => void sink.lines.push(l) } } }),
  };
});

const CODE = "nspk:agent:journalscan:v1";

/** Сторона агента с известным тесту закрытым ключом; каждая подпись запоминается. */
function knownSide(): { side: AgentSide; secrets: string[]; signatures: Buffer[] } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const kid = agentKid(pub);
  const signatures: Buffer[] = [];
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const d = (privateKey.export({ format: "jwk" }) as { d: string }).d;
  const raw = Buffer.from(d, "base64url");
  const secrets = [
    pkcs8.toString("base64"),
    pkcs8.toString("hex"),
    String(privateKey.export({ type: "pkcs8", format: "pem" })).split("\n")[1] as string,
    d,
    raw.toString("base64"),
    raw.toString("hex"),
  ];
  const signer = {
    kid,
    alg: "ed25519" as const,
    sign: (data: Buffer) => {
      const s = cSign(null, data, privateKey);
      signatures.push(s);
      return s;
    },
  };
  return { side: { signer, publicKey: pub, kid } as AgentSide, secrets, signatures };
}

/** Шестнадцатеричные строки от 32 знаков — хэши цепочки и отпечатки, не номер карты: иначе ложные серии по Луну. */
const HEX_LONG = /\b[0-9a-f]{32,}\b/gi;
/**
 * Числовые метрики pino и Fastify — не номер карты: time (мс, 13 цифр) и responseTime (дробная часть даёт серию 13–19
 * цифр, по Луну проходит случайно — первый прогон К3). Остальные поля сканируются целиком.
 */
const METRICS = ["time", "responseTime"] as const;
const panIn = (line: string): boolean => {
  let v: unknown;
  try {
    v = JSON.parse(line);
  } catch {
    return hasPaymentDetails(line.replace(HEX_LONG, "#"));
  }
  if (v && typeof v === "object" && !Array.isArray(v)) for (const k of METRICS) delete (v as Record<string, unknown>)[k];
  return hasPaymentDetails(JSON.stringify(v).replace(HEX_LONG, "#"));
};

describe("сканер журналов: реквизитов, ключей и подписей нет (Ж4, SPEC §11 п. 7)", () => {
  let stand: Stand;
  const known = knownSide();
  const principal = opaquePrincipalRef("prn_scan_");
  const out: string[] = [];
  const restore: (() => void)[] = [];
  let cryptogram = "";
  let op = "";
  const mandates: string[] = [];
  const evidence: string[] = [];

  beforeAll(async () => {
    // Побочный вывод мимо логгера — на время прогона: console.* и запись в stdout / stderr.
    for (const m of ["log", "info", "warn", "error", "debug", "trace"] as const) {
      const spy = vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void out.push(a.map(String).join(" ")));
      restore.push(() => spy.mockRestore());
    }
    for (const s of [process.stdout, process.stderr]) {
      const orig = s.write.bind(s);
      s.write = ((chunk: unknown, ...rest: unknown[]) => {
        out.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
        return (orig as (...x: unknown[]) => boolean)(chunk, ...rest);
      }) as typeof s.write;
      restore.push(() => {
        s.write = orig;
      });
    }

    stand = createStand();
    stand.setClock(new Date("2026-10-23T15:20:00Z"));
    expect((await stand.admit(buyerApplication(CODE, known.side), "op")).admitted).toBe(true);
    // Ответы POST /pao/v1/credentials — для credential_ref (standPay его не возвращает).
    const issued: string[] = [];
    const inject = stand.app.inject.bind(stand.app);
    const spy = vi.spyOn(stand.app, "inject").mockImplementation((async (o: string | { method?: string; url?: unknown }) => {
      const r = await inject(o as never);
      if (typeof o === "object" && o.method === "POST" && String(o.url) === "/pao/v1/credentials" && r.statusCode === 201) {
        issued.push((r.json() as { credential_ref: string }).credential_ref);
      }
      return r;
    }) as never);
    restore.push(() => spy.mockRestore());
    const pay = standPay(stand, known.side, CODE, principal);
    const intent = await pay.mandate({ amount_limit: 100_000 });
    const cart = await pay.cart(intent, 100_000);
    mandates.push(intent, cart);
    op = `OPKC-SCAN-${letters(12)}`;
    const msg: CanonicalMessage = await pay.auth(cart, 60_000, op);
    cryptogram = String(msg.instrument.cryptogram);
    const decide = (await stand.app.inject({ method: "POST", url: "/adp/v1/decide", payload: msg })).json() as Decision;
    expect(decide).toMatchObject({ decision: "APPROVE" });
    const pi3 = async (payload: Record<string, unknown>) =>
      (await stand.app.inject({ method: "POST", url: "/adp/v1/events", payload })).statusCode;
    expect(await pi3({ op_ref: op, msg_type: "ISSUER_RESPONSE", issuer_approved: true })).toBe(202);
    expect(await pi3({ op_ref: op, msg_type: "PRESENTMENT", amount: 60_000, currency: "RUB" })).toBe(202);
    expect(await pi3({ op_ref: op, msg_type: "REFUND", amount: 60_000, currency: "RUB", refund_ref: `RF-${randomUUID()}` })).toBe(202);
    const get = (path: string) => signedInject(stand.app, known.side, CODE, { method: "GET", path, now: stand.now() });
    // Реквизит по ссылке — второй путь выдачи значения криптограммы (GET пересчитывает её).
    expect(issued).toHaveLength(1);
    const again = await get(`/pao/v1/credentials/${issued[0] as string}`);
    expect(again.statusCode).toBe(200);
    expect((again.json() as { payload: { cryptogram: string } }).payload.cryptogram).toBe(cryptogram);
    for (const id of mandates) {
      const r = await get(`/pao/v1/mandates/${id}/evidence`);
      expect(r.statusCode).toBe(200);
      evidence.push(r.body);
    }
  });

  afterAll(async () => {
    for (const r of restore.reverse()) r();
    await stand?.close();
  });

  it("положительный контроль: путь прошёл, значения известны, журналы не пусты", () => {
    expect(cryptogram.length).toBeGreaterThan(0);
    // Подписаны: два мандата, реквизит, GET реквизита, две выписки.
    expect(known.signatures.length).toBeGreaterThanOrEqual(5);
    expect(known.secrets.every((s) => s.length >= 32)).toBe(true);
    const routes = sink.lines.map((l) => JSON.parse(l) as { msg?: string; req?: { method?: string; route?: string } });
    const seen = (method: string, route: string) =>
      routes.some((e) => e.msg === "incoming request" && e.req?.method === method && e.req?.route === route);
    for (const [m, r] of [
      ["POST", "/pao/v1/mandates"],
      ["POST", "/pao/v1/credentials"],
      ["POST", "/adp/v1/decide"],
      ["POST", "/adp/v1/events"],
      ["GET", "/pao/v1/mandates/:id/evidence"],
      ["GET", "/pao/v1/credentials/:ref"],
    ] as const) {
      expect(seen(m, r), `${m} ${r} в журнале процесса`).toBe(true);
    }
    const calls = stand.calls();
    expect(calls.some((c) => c.path === "/adp/v1/events" && c.status === 202)).toBe(true);
    expect(calls.filter((c) => c.kid === known.side.kid).length).toBe(known.signatures.length);
    // Журнал согласий: у каждого мандата — запрос и подпись банка.
    for (const body of evidence) {
      const kinds = (JSON.parse(body) as { records: { kind: string }[] }).records.map((r) => r.kind);
      expect(kinds.length).toBeGreaterThanOrEqual(2);
    }
  });

  it("номера карты по Луну нет ни в одном журнале и в побочном выводе", () => {
    const hits = [
      ...sink.lines.filter(panIn).map((l) => `процесс: ${l}`),
      ...evidence.filter(panIn).map((l) => `согласия: ${l}`),
      ...stand.calls().map((c) => JSON.stringify(c)).filter(panIn).map((l) => `обращения: ${l}`),
      ...out.filter(panIn).map((l) => `вывод: ${l}`),
    ];
    expect(hits).toEqual([]);
  });

  it("выданной криптограммы, закрытого ключа агента и значений его подписей нет — сравнением с использованными", () => {
    const all = [...sink.lines, ...evidence, ...stand.calls().map((c) => JSON.stringify(c)), ...out].join("\n");
    expect(all.includes(cryptogram), "криптограмма").toBe(false);
    for (const s of known.secrets) expect(all.includes(s), "закрытый ключ агента").toBe(false);
    for (const sig of known.signatures) {
      for (const v of [sig.toString("base64"), sig.toString("base64url"), sig.toString("hex")]) {
        expect(all.includes(v), "значение подписи агента").toBe(false);
      }
    }
    expect(/PRIVATE KEY/.test(all), "PEM закрытого ключа").toBe(false);
    expect(/"d"\s*:\s*"[A-Za-z0-9_-]{40,}"/.test(all), "JWK с d").toBe(false);
  });
});

/**
 * Страж имён (вариант (В) владельца, К3 сессии 66): стенд не передаёт log компонентам (П3, П5, П8, ADP) — их записи
 * живой сканер выше не видит. Поэтому в аргументах каждого вызова журнала в src (строковые литералы не в счёт — это
 * тексты сообщений) запрещены имена с сырыми секретами. Предел: значение под другим именем ({ value: c }) страж не ловит —
 * остаточный риск SECURITY Ж4.
 */
const FORBIDDEN_IN_LOG = /\b(?:cryptogram|payload|privateKey|private_key|signature|secret|pan|cvv|cvc|track[12]?)\b/i;
const withoutStrings = (s: string): string => s.replace(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""');

describe("страж: в аргументах вызовов журнала в src — без имён сырых секретов (Ж4)", () => {
  it("cryptogram, payload, ключ, подпись, номер и CVV — ни в одном вызове журнала", () => {
    const found: string[] = [];
    let n = 0;
    for (const [f, text] of srcFiles()) {
      for (const [call, args] of calls(text, LOG_CALL)) {
        n++;
        const m = FORBIDDEN_IN_LOG.exec(withoutStrings(args));
        if (m) found.push(`${f}: ${call}${args.slice(0, 100)} — «${m[0]}»`);
      }
    }
    expect(n).toBeGreaterThan(150);
    expect(found).toEqual([]);
  });

  it("страж видит имя в поле и в значении, но не в тексте сообщения; хэш криптограммы — не секрет", () => {
    const hit = (args: string) => FORBIDDEN_IN_LOG.test(withoutStrings(args));
    expect(hit("{ credential_ref, cryptogram }, \"П5\"")).toBe(true);
    expect(hit("{ v: rec.payload.token_ref }, \"x\"")).toBe(true);
    expect(hit("{ op_ref }, \"ADP: криптограмма уже погашена, signature\"")).toBe(false);
    expect(hit("{ h: prior.cryptogram_sha256 }, \"x\"")).toBe(false);
  });
});
