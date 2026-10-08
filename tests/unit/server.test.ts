import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer, parseEnv } from "../../src/server.js";

describe("каркас сервера", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
  });

  it("GET /health отвечает без базы данных", async () => {
    app = buildServer({ env: "dev" });
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok", env: "dev" });
  });

  it("среда по умолчанию — dev", () => {
    expect(parseEnv(undefined)).toBe("dev");
    expect(parseEnv("sandbox")).toBe("sandbox");
  });

  it("неизвестная среда — отказ запуска", () => {
    expect(() => parseEnv("prod")).toThrow(/PLATFORM_ENV/);
  });
});
