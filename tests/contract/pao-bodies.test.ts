// Тела изменяющих методов ПАО: ручная проверка схемы (src/pao/body.ts) против agent-protocol.yaml (РП31 п. 1).
// Когда изменяющих методов станет больше двух-трёх — валидатор по схеме отдельным решением (ревью к плану сессии 10).
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { KEY_REGISTRATION_REQUIRED, MANDATE_REQUEST_REQUIRED, mandateRequestBody } from "../../src/pao/index.js";

const pao = parse(readFileSync("docs/core/agent-protocol.yaml", "utf8"), { maxAliasCount: -1 });

describe("тело POST /pao/v1/agent/keys — по схеме ПАО", () => {
  const op = pao.paths["/pao/v1/agent/keys"].post;
  const schema = op.requestBody.content["application/json"].schema;

  it("обязательные поля совпадают с required схемы, все — строки", () => {
    expect([...KEY_REGISTRATION_REQUIRED].sort()).toEqual([...schema.required].sort());
    for (const f of KEY_REGISTRATION_REQUIRED) expect(schema.properties[f].type).toBe("string");
  });

  it("в схеме нет полей сверх обязательных — проверять нечего больше", () => {
    expect(Object.keys(schema.properties).sort()).toEqual([...KEY_REGISTRATION_REQUIRED].sort());
  });

  // 403 AGENT_SUSPENDED метод отдаёт (РП23 п. 6.3), но в ответах YAML его нет — расхождение, к ПАО 1.5.0 (РП37, STATUS).
  it("ответы метода — по РП31 п. 3: 201, 400, 401, 409, 422, 503", () => {
    expect(Object.keys(op.responses).sort()).toEqual(["201", "400", "401", "409", "422", "503"]);
    expect(pao.paths["/pao/v1/agent/keys"].post.parameters.map((p: { $ref?: string }) => p.$ref)).toContain(
      "#/components/parameters/IdempotencyKey",
    );
  });
});

describe("тело POST /pao/v1/mandates — по схеме MandateRequest (PS-06 К1.3)", () => {
  const schema = pao.components.schemas.MandateRequest;
  const valid = {
    type: "INTENT",
    subject: "s",
    amount_limit: 1,
    currency: "RUB",
    valid_to: "2030-01-01T00:00:00Z",
    merchant_scope: [],
    principal_ref: "prn_1",
    mode: "IMMEDIATE",
  };

  it("обязательные поля совпадают с required схемы; без любого из них — undefined", () => {
    expect([...MANDATE_REQUEST_REQUIRED].sort()).toEqual([...schema.required].sort());
    expect(mandateRequestBody(JSON.stringify(valid))).toBeDefined();
    for (const f of MANDATE_REQUEST_REQUIRED) {
      const { [f]: _drop, ...rest } = valid;
      void _drop;
      expect(mandateRequestBody(JSON.stringify(rest)), f).toBeUndefined();
    }
  });

  it("перечни type, mode, settlement_mode и minimum amount_limit — как в схеме", () => {
    const p = schema.properties;
    for (const [field, values] of [
      ["type", p.type.enum],
      ["mode", p.mode.enum],
      ["settlement_mode", p.settlement_mode.enum],
    ] as const) {
      for (const val of values as string[]) {
        const body = field === "settlement_mode" && val === "CONDITIONAL" ? { ...valid, [field]: val, conditional: { provider: "cx:nsvr" } } : { ...valid, [field]: val };
        expect(mandateRequestBody(JSON.stringify(body)), `${field}=${val}`).toBeDefined();
      }
      expect(mandateRequestBody(JSON.stringify({ ...valid, [field]: "OTHER" })), field).toBeUndefined();
    }
    expect(p.amount_limit.minimum).toBe(1);
    expect(mandateRequestBody(JSON.stringify({ ...valid, amount_limit: 0 }))).toBeUndefined();
    expect(p.valid_to.format).toBe("date-time");
    expect(mandateRequestBody(JSON.stringify({ ...valid, valid_to: "Oct 1 2030" }))).toBeUndefined();
  });

  it("возвращаются только поля схемы", () => {
    const out = mandateRequestBody(JSON.stringify({ ...valid, signature_type: "qualified", extra_field: "x" }))!;
    for (const k of Object.keys(out)) expect(Object.keys(schema.properties)).toContain(k);
  });
});

describe("ответы POST /pao/v1/mandates — по РП33 п. 3", () => {
  it("201, 400, 401, 403, 404, 409, 503; ключ идемпотентности — в параметрах", () => {
    const op = pao.paths["/pao/v1/mandates"].post;
    expect(Object.keys(op.responses).sort()).toEqual(["201", "400", "401", "403", "404", "409", "503"]);
    expect(op.parameters.map((p: { $ref?: string }) => p.$ref)).toContain("#/components/parameters/IdempotencyKey");
  });
});

describe("ответы GET /pao/v1/mandates/{id} — по РП34 п. 4", () => {
  it("200, 401, 403, 404, 503; 200 — схема Mandate", () => {
    const op = pao.paths["/pao/v1/mandates/{id}"].get;
    expect(Object.keys(op.responses).sort()).toEqual(["200", "401", "403", "404", "503"]);
    expect(op.responses["200"].content["application/json"].schema.$ref).toBe("#/components/schemas/Mandate");
  });
});

// Ответы 400/401/403/503 лента отдаёт, а в YAML их нет — объявить в ПАО 1.5.0 (РП39 п. 8, № 20): тогда тест покраснеет.
describe("GET /pao/v1/events — по схеме Event (PS-08 К1.2, РП39)", () => {
  const op = pao.paths["/pao/v1/events"].get;
  const event = pao.components.schemas.Event;

  it("параметр after — строка в запросе; ответ 200 — массив Event; других ответов в 1.4.0 нет", () => {
    expect(op.parameters.find((p: { name?: string }) => p.name === "after")).toMatchObject({ in: "query", schema: { type: "string" } });
    expect(Object.keys(op.responses)).toEqual(["200"]);
    expect(op.responses["200"].content["application/json"].schema).toEqual({
      type: "array",
      items: { $ref: "#/components/schemas/Event" },
    });
  });

  it("событие ленты — ровно required схемы; типы событий мандата — из перечня; data — объект", () => {
    expect([...event.required].sort()).toEqual(["at", "data", "event_id", "type"]);
    expect(Object.keys(event.properties).sort()).toEqual([...event.required].sort());
    for (const t of ["mandate.signed", "mandate.rejected", "mandate.revoked"]) expect(event.properties.type.enum).toContain(t);
    expect(event.properties.data.type).toBe("object");
    expect(event.properties.at.format).toBe("date-time");
  });
});
