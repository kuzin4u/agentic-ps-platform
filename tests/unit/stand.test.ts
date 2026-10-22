// РП25: стенд для тестов агента — среда dev, контур ключей sandbox; параметры — Платформы, не текущего каталога.
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { PaoClient } from "@kuzin4u/agentic-core/pao";
import { afterEach, describe, expect, it } from "vitest";
import { createStand, type Stand } from "../../src/stand/index.js";
import { loadParams } from "../../src/shared/config.js";
import { buyerApplication, newAgentSide } from "../support/agent.js";

const CODE = "nspk:agent:buyref-01:v3";

describe("РП25: стенд для тестов агента", () => {
  let s: Stand | undefined;
  afterEach(async () => {
    await s?.close();
    s = undefined;
  });

  it("допуск в контуре sandbox и GET /pao/v1/agent клиентом core по HTTP — 200", async () => {
    s = createStand();
    const side = newAgentSide();
    expect(s.admit(buyerApplication(CODE, side), "buyref-operator").admitted).toBe(true);
    const baseUrl = await s.listen();
    const self = await new PaoClient({ baseUrl, agentCode: CODE, signer: side.signer, maxAttempts: 1 }).call(
      "GET /pao/v1/agent",
      {},
    );
    expect(self).toMatchObject({ agent_code: CODE, status: "ACTIVE", keys: [{ kid: side.kid }] });
  });

  it("среда — dev, а не sandbox: стенд песочницей не является", async () => {
    s = createStand();
    // Уведомитель участников и сборщик итогов стенда — в /health (ревью КТ1 PS-20 ч. 3, РП52 «Дополнения» п. 2): проходов
    // ещё не было, отставания нет.
    expect((await s.app.inject({ method: "GET", url: "/health" })).json()).toEqual({
      status: "ok",
      env: "dev",
      participant_notify: { last_pass_at: null, lagging: false },
      operation_outcome: { last_pass_at: null, lagging: false },
    });
  });

  it("параметры по умолчанию — от корня пакета Платформы, чужой config/ в текущем каталоге не читается", () => {
    // Отдельный процесс с другим cwd: process.chdir в воркере vitest зависит от пула.
    const dir = mkdtempSync(join(tmpdir(), "stand-cwd-"));
    try {
      mkdirSync(join(dir, "config"));
      writeFileSync(join(dir, "config", "params.stand.json"), "{ не JSON");
      const config = pathToFileURL(resolve(import.meta.dirname, "../../src/shared/config.ts")).href;
      const code = `const { loadParams } = await import(${JSON.stringify(config)}); console.log(loadParams().signature_skew_sec);`;
      const env = { ...process.env };
      delete env.PARAMS_PATH;
      const out = execFileSync(
        process.execPath,
        ["--import", import.meta.resolve("tsx"), "--input-type=module", "-e", code],
        { cwd: dir, env, encoding: "utf8" },
      );
      expect(Number(out.trim())).toBe(loadParams().signature_skew_sec);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
