// Р-1374: маршруты ПИ-8 и ПАО с хранилищем П6 без прохода закрытия после отзыва (РП76) не стартуют — в любой сборке
// (main.ts, buildServer, стенд, тесты). Основная защита — тип (closeRevoked обязателен рядом с хранилищем П6), здесь —
// запасная проверка при старте: сборка в обход типа (приведение) получает исключение.
import Fastify from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryConfirmationStore } from "../../src/confirm/index.js";
import { paoRoutes, type PaoDeps } from "../../src/pao/routes.js";
import { participantRoutes, type ParticipantDeps } from "../../src/participants/routes.js";
import { createStand, type Stand } from "../../src/stand/index.js";

let st: Stand | undefined;
afterEach(async () => {
  await st?.close();
  st = undefined;
});

const store = new MemoryConfirmationStore();

describe("Р-1374: П6 без прохода РП76 — исключение при старте маршрутов", () => {
  it("participantRoutes: confirmations без closeRevoked — исключение", async () => {
    const deps = { confirmations: { store, skewSec: 30 } } as unknown as ParticipantDeps;
    await expect(participantRoutes(Fastify(), deps)).rejects.toThrow(/participantRoutes: хранилище П6 без прохода/);
  });

  it("paoRoutes: confirmations без closeRevoked — исключение", async () => {
    const deps = { confirmations: { store, now: () => new Date(), upk_page_base_url: "https://upk.stand" } } as unknown as PaoDeps;
    await expect(paoRoutes(Fastify(), deps)).rejects.toThrow(/paoRoutes: хранилище П6 без прохода/);
  });

  it("с П6 и проходом — стенд стартует (ПИ-8 и ПАО с confirmations и closeRevoked)", async () => {
    st = createStand();
    await expect(st.app.ready()).resolves.toBeDefined();
  });
});
