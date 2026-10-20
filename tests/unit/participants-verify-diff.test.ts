// Подпись запроса участника против ядра (PS-20 ч. 2 К1.4а, ревью З11; передача agentic-core #39): ParticipantRequestVerifier
// повторяет порядок проверок verifyRequestAsync ядра с x-participant-code вместо x-agent-code. Векторов подписи HTTP в
// ядре нет, поэтому сверка дифференциальная: один ключ, одни и те же запросы и искажения — ядро (профиль агента) и
// проверка участника обязаны дать один исход. Расхождение — красный тест. Снимается, когда ядро примет состав параметром.
// Сознательное отличие: ядро принимает состав «не меньше обязательного», участник — ровно PARTICIPANT_COMPONENTS (РП46 (в)).
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { DEFAULT_COMPONENTS, signRequest, verifyRequestAsync, type HttpLike, type Signer } from "@kuzin4u/agentic-core";
import { describe, expect, it } from "vitest";
import { TrustedParticipants } from "../../src/participants/trusted.js";
import { PARTICIPANT_COMPONENTS, ParticipantRequestVerifier } from "../../src/participants/verify.js";
import { jwkThumbprint } from "../../src/registry/keys.js";

const CODE = "bank:diff";
const NOW = new Date("2026-10-20T10:00:00Z");
const SKEW = 300;

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUB = publicKey.export({ type: "spki", format: "der" }).toString("base64");
const { crv, kty, x } = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
const KID = jwkThumbprint({ crv, kty, x });
const signer: Signer = { kid: KID, alg: "ed25519", sign: (d) => edSign(null, d, privateKey) };

type Req = { method: string; path: string; query: string; body: string; headers: Record<string, string> };
type Mutation = { name: string; before?: (r: Req) => void; after?: (r: Req) => void; at?: Date; twice?: boolean };

/** Запрос в профиле: who — заголовок кода (x-agent-code у ядра, x-participant-code у участника). */
function signed(who: "x-agent-code" | "x-participant-code", m: Mutation, nonce: string): Req {
  const r: Req = {
    method: "GET",
    path: "/participants/v1/principals/prn_7f3c9a/limits",
    query: "",
    body: "",
    headers: { [who]: CODE, "x-timestamp": (m.at ?? NOW).toISOString(), "x-nonce": nonce },
  };
  m.before?.(r);
  const out = signRequest(r as HttpLike, signer, who === "x-agent-code" ? DEFAULT_COMPONENTS : PARTICIPANT_COMPONENTS) as Req;
  const copy: Req = { ...out, headers: { ...out.headers } };
  m.after?.(copy);
  return copy;
}

const MUTATIONS: Mutation[] = [
  { name: "верный запрос" },
  { name: "метка на краю окна", at: new Date(NOW.getTime() - SKEW * 1000) },
  { name: "метка вне окна", at: new Date(NOW.getTime() - (SKEW + 1) * 1000) },
  { name: "метка не дата", after: (r) => (r.headers["x-timestamp"] = "вчера") },
  { name: "путь изменён после подписи", after: (r) => (r.path = "/participants/v1/principals/prn_other1/limits") },
  { name: "запрос изменён после подписи", after: (r) => (r.query = "x=1") },
  { name: "метод изменён после подписи", after: (r) => (r.method = "PUT") },
  { name: "тело не соответствует digest", after: (r) => (r.body = "{}") },
  { name: "digest удалён", after: (r) => delete r.headers["content-digest"] },
  { name: "подпись искажена", after: (r) => (r.headers["signature"] = r.headers["signature"]!.replace(/:(.)/, (_m, c: string) => `:${c === "A" ? "B" : "A"}`)) },
  { name: "подпись удалена", after: (r) => delete r.headers["signature"] },
  { name: "неизвестный kid", after: (r) => (r.headers["signature-input"] = r.headers["signature-input"]!.replace(KID, "kid-unknown")) },
  { name: "другой алгоритм", after: (r) => (r.headers["signature-input"] = r.headers["signature-input"]!.replace('alg="ed25519"', 'alg="rsa"')) },
  { name: "nonce удалён", after: (r) => delete r.headers["x-nonce"] },
  { name: "nonce изменён после подписи", after: (r) => (r.headers["x-nonce"] = `${r.headers["x-nonce"]}x`) },
  { name: "повтор nonce", twice: true },
];

describe("ParticipantRequestVerifier = verifyRequestAsync ядра по исходу (З11, до agentic-core #39)", () => {
  it("состав подписи участника — состав ядра с x-participant-code вместо x-agent-code", () => {
    expect(PARTICIPANT_COMPONENTS.map((c) => (c === "x-participant-code" ? "x-agent-code" : c))).toEqual([...DEFAULT_COMPONENTS]);
  });

  it.each(MUTATIONS.map((m, i) => [m.name, m, i] as const))("%s — один исход", async (_n, m, i) => {
    const seen = new Set<string>();
    const core = async (r: Req) =>
      (
        await verifyRequestAsync(
          r,
          (kid) => (kid === KID ? { alg: "ed25519", publicKey: PUB, status: "ACTIVE" as const } : undefined),
          {
            now: NOW.getTime(),
            skewSec: SKEW,
            seenNonce: async (n) => {
              if (n === "" || seen.has(n)) return true;
              seen.add(n);
              return false;
            },
          },
        )
      ).ok;
    const trusted = new TrustedParticipants([{ participant_code: CODE, kid: KID, alg: "ed25519", public_key: PUB, revocation_order: "bank:diff:revocation:v1" }], {
      stand: true,
    });
    const own = new ParticipantRequestVerifier(trusted, { skewSec: SKEW, now: () => NOW });
    const ours = async (r: Req) => (await own.verify(r)).ok;

    const a = signed("x-agent-code", m, `nonce-${i}`);
    const p = signed("x-participant-code", m, `nonce-${i}`);
    const coreFirst = await core(a);
    const oursFirst = await ours(p);
    expect(oursFirst, `исход проверки участника ≠ ядру: «${m.name}»`).toBe(coreFirst);
    if (m.twice) {
      const coreAgain = await core(a);
      const oursAgain = await ours(p);
      expect(coreAgain, "ядро приняло повтор nonce").toBe(false);
      expect(oursAgain, `исход повтора ≠ ядру: «${m.name}»`).toBe(coreAgain);
    }
  });

  it("сознательное отличие: лишний компонент в составе — ядро принимает, участник — нет (ровно состав, РП46 (в))", async () => {
    const r: Req = {
      method: "GET",
      path: "/participants/v1/principals/prn_7f3c9a/limits",
      query: "",
      body: "",
      headers: { "x-participant-code": CODE, "x-timestamp": NOW.toISOString(), "x-nonce": "n-extra", "x-extra": "1" },
    };
    const out = signRequest(r as HttpLike, signer, [...PARTICIPANT_COMPONENTS, "x-extra"]) as Req;
    const trusted = new TrustedParticipants([{ participant_code: CODE, kid: KID, alg: "ed25519", public_key: PUB, revocation_order: "bank:diff:revocation:v1" }], {
      stand: true,
    });
    expect((await new ParticipantRequestVerifier(trusted, { skewSec: SKEW, now: () => NOW }).verify(out)).ok).toBe(false);
  });
});
