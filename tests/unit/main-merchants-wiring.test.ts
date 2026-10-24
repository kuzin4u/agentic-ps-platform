// Подключение API продавцов и маршрутов РП56–РП57 в рабочем сервере (PS-30 ч. 2 К3; КТ1 сессии 37): процесс src/main.ts
// в среде dev без базы — каталог ключей, статус агента, знак готовности продавцу, ПИ-8 эквайрера (знак, статус агента)
// и путь знака в ПАО зарегистрированы; метаданные пакета и сверка — нет (П5 в рабочем сервере нет, РП57 доп. 5).
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { describe, expect, it } from "vitest";
import { loadParams } from "../../src/shared/config.js";

const MAIN = ["--import", import.meta.resolve("tsx"), "src/main.ts"];

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => (typeof addr === "object" && addr ? resolve(addr.port) : reject(new Error("нет порта"))));
    });
  });
}

describe("src/main.ts: API продавцов и маршруты эквайрера подключены (РП56, РП57)", () => {
  it("dev без базы: адреса продавца, ПИ-8 эквайрера и ПАО-путь знака отвечают своими кодами; …/payments не зарегистрирован", async () => {
    const port = await freePort();
    const child = spawn(process.execPath, MAIN, { env: { PATH: process.env.PATH, HOME: process.env.HOME, PLATFORM_ENV: "dev", PORT: String(port) } });
    let out = "";
    child.stdout.on("data", (b: Buffer) => void (out += b.toString()));
    child.stderr.on("data", (b: Buffer) => void (out += b.toString()));
    const base = `http://127.0.0.1:${port}`;
    try {
      let health: Response | undefined;
      for (let i = 0; i < 200 && !health; i++) {
        health = await fetch(`${base}/health`).catch(async () => {
          await new Promise((r) => setTimeout(r, 100));
          return undefined;
        });
      }
      expect(health?.status, out).toBe(200);
      const get = (path: string) => fetch(`${base}${path}`);
      const post = (path: string) => fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });

      const keys = await get("/.well-known/agent-keys");
      expect([keys.status, keys.headers.get("content-type")]).toEqual([200, "application/jwk-set+json"]);
      const agent = await get("/merchants/v1/agents/nspk:agent:none:v1");
      expect([agent.status, await agent.json()]).toEqual([404, { code: "AGENT_UNKNOWN" }]);
      const mark = await get("/merchants/v1/merchants/MER-1042/readiness");
      expect([mark.status, await mark.json()]).toEqual([200, { merchant_id: "MER-1042", status: "NONE", since: null }]);
      expect(mark.headers.get("cache-control")).toBe(`public, max-age=${loadParams().merchant_readiness_max_age_sec}`);

      // ПИ-8 эквайрера: маршрут есть — тело не по форме (400) или нет подписи (401), а не 404.
      expect((await post("/participants/v1/merchants/MER-1042/readiness")).status).toBe(400);
      expect((await get("/participants/v1/merchants/MER-1042/readiness")).status).toBe(401);
      expect((await get("/participants/v1/agents/nspk:agent:none:v1/status")).status).toBe(401);
      // ПАО: путь знака зарегистрирован — проверка обращения отвечает 401 по ПАО §6; незарегистрированный путь — 404.
      const pao = await get("/pao/v1/merchants/MER-1042/readiness");
      expect([pao.status, ((await pao.json()) as { code: string }).code]).toEqual([401, "AGENT_UNKNOWN"]);
      expect((await get("/pao/v1/no-such-route")).status).toBe(404);
      // Метаданные и сверка — только стенд (РП57 доп. 5): в рабочем сервере маршрутов нет.
      expect((await post("/participants/v1/merchants/MER-1042/payments")).status).toBe(404);
    } finally {
      child.kill("SIGTERM");
    }
  }, 40_000);
});
