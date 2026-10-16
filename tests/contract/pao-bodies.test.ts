// Тела изменяющих методов ПАО: ручная проверка схемы (src/pao/body.ts) против agent-protocol.yaml (РП31 п. 1).
// Когда изменяющих методов станет больше двух-трёх — валидатор по схеме отдельным решением (ревью к плану сессии 10).
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { KEY_REGISTRATION_REQUIRED } from "../../src/pao/index.js";

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

  // 403 AGENT_SUSPENDED метод отдаёт (РП23 п. 6.3), но в ответах YAML его нет — расхождение, к ПАО 1.4.0 (STATUS).
  it("ответы метода — по РП31 п. 3: 201, 400, 401, 409, 422, 503", () => {
    expect(Object.keys(op.responses).sort()).toEqual(["201", "400", "401", "409", "422", "503"]);
    expect(pao.paths["/pao/v1/agent/keys"].post.parameters.map((p: { $ref?: string }) => p.$ref)).toContain(
      "#/components/parameters/IdempotencyKey",
    );
  });
});
