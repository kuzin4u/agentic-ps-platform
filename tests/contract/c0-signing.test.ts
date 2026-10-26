// Точка сверки С0 (joint-plan): подпись агента принимается Платформой. Заготовка совместного теста до AG-03.
// Агент подписывает клиентом ПАО из agentic-core по HTTP; Платформа проверяет тем же кодом core (РП23 п. 6).
// kid клиент вычисляет сам по RFC 7638 из своего public_key — из ответа реестра не берёт.
import { PaoCallError, PaoClient } from "@kuzin4u/agentic-core/pao";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { agentKid, buyerApplication, newAgentSide, type AgentSide } from "../support/agent.js";
import { stand, type Stand } from "../support/stand.js";

const CODE = "nspk:agent:buyref-01:v3";

describe("С0: агент подписал — Платформа приняла", () => {
  let s: Stand;
  let baseUrl: string;

  beforeEach(async () => {
    s = stand();
    await s.app.listen({ host: "127.0.0.1", port: 0 });
    const addr = s.app.server.address();
    if (!addr || typeof addr === "string") throw new Error("нет адреса сервера");
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });
  afterEach(async () => {
    await s.app.close();
  });

  const admit = async (side: AgentSide): Promise<void> => {
    const d = await s.registry.admit(buyerApplication(CODE, side), { contour: "sandbox", operator: "buyref-operator" });
    expect(d.admitted).toBe(true);
  };
  const client = (side: AgentSide, agentCode = CODE): PaoClient =>
    new PaoClient({ baseUrl, agentCode, signer: side.signer, maxAttempts: 1 });

  it("kid агента по RFC 7638 — эталон RFC 8037 прил. A.3", () => {
    const spki = Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "base64url"),
    ]).toString("base64");
    expect(agentKid(spki)).toBe("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  });

  it("GET /pao/v1/agent клиентом core с kid, вычисленным агентом, — 200; kid совпал с выданным реестром", async () => {
    const side = newAgentSide();
    await admit(side);
    const self = await client(side).call("GET /pao/v1/agent", {});
    expect(self).toMatchObject({ agent_code: CODE, class: "BUYER", level: 1, status: "ACTIVE" });
    // Сверка после вызова: kid агента и kid реестра вычислены независимо и совпали.
    expect(self.keys?.map((k) => k.kid)).toEqual([side.kid]);
  });

  it("чужой ключ под своим кодом — 401 SIGNATURE_INVALID, retry after_fix", async () => {
    await admit(newAgentSide());
    const err = await client(newAgentSide())
      .call("GET /pao/v1/agent", {})
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PaoCallError);
    expect(err).toMatchObject({ status: 401, code: "SIGNATURE_INVALID", retry: "after_fix" });
  });

  it("не тот kid у своего ключа — 401 SIGNATURE_INVALID: kid выдумывать нельзя", async () => {
    const side = newAgentSide();
    await admit(side);
    const wrong: AgentSide = { ...side, signer: { ...side.signer, kid: "k-2026-10" } };
    await expect(client(wrong).call("GET /pao/v1/agent", {})).rejects.toMatchObject({
      status: 401,
      code: "SIGNATURE_INVALID",
    });
  });

  it("агента нет в реестре — 401 AGENT_UNKNOWN, retry never", async () => {
    await expect(client(newAgentSide(), "nspk:agent:nobody:v1").call("GET /pao/v1/agent", {})).rejects.toMatchObject({
      status: 401,
      code: "AGENT_UNKNOWN",
      retry: "never",
    });
  });
});
