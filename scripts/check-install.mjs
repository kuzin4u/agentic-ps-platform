// РП25: проверка стенда так, как его подключит агент — установкой во временный каталог вне репозитория.
//   node scripts/check-install.mjs --pack          — из `npm pack` текущего дерева;
//   node scripts/check-install.mjs --git <ref>     — по git+https#<ref> (ветка, тег, коммит), с `prepare`.
// --git проверяет то, что уже отправлено на GitHub, а не локальное рабочее дерево: до отправки — проверяйте --pack.
// В каталоге установки лежит заведомо неверный config/params.stand.json: стенд должен читать параметры Платформы.
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO = "https://github.com/kuzin4u/agentic-ps-platform.git";
const [mode, ref] = process.argv.slice(2);
if (!(mode === "--pack" || (mode === "--git" && ref))) {
  console.error("Использование: check-install.mjs --pack | --git <ref>");
  process.exit(2);
}

const ROOT = resolve(import.meta.dirname, "..");
// check.mjs импортирует agentic-core сам — зависимость объявлена явно, тем же спецификатором, что у Платформы.
const CORE = "@kuzin4u/agentic-core";
const coreSpec = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).dependencies[CORE];
if (!coreSpec) throw new Error(`нет ${CORE} в dependencies Платформы`);

const npm = (args, cwd) => execFileSync("npm", args, { cwd, stdio: ["ignore", "pipe", "inherit"], encoding: "utf8" });
const work = mkdtempSync(join(tmpdir(), "ps-stand-install-"));
try {
  let spec;
  if (mode === "--pack") {
    const packDir = join(work, "pack");
    mkdirSync(packDir);
    npm(["pack", "--pack-destination", packDir, ROOT]);
    spec = join(packDir, readdirSync(packDir).find((f) => f.endsWith(".tgz")));
  } else {
    spec = `git+${REPO}#${ref}`;
  }

  const app = join(work, "consumer");
  mkdirSync(join(app, "config"), { recursive: true });
  writeFileSync(
    join(app, "package.json"),
    JSON.stringify({ name: "consumer", private: true, type: "module", dependencies: { [CORE]: coreSpec } }),
  );
  writeFileSync(join(app, "config", "params.stand.json"), "{ не параметры Платформы");
  npm(["install", "--no-audit", "--no-fund", spec], app);

  writeFileSync(
    join(app, "check.mjs"),
    `
import { createHash, createPublicKey } from "node:crypto";
import { createMerchants, createStand } from "agentic-ps-platform/stand";
import { AGENT_FIXTURES, MERCHANT_FIXTURES } from "agentic-ps-platform/fixtures";
import { newEd25519Signer } from "@kuzin4u/agentic-core";
import { PaoClient } from "@kuzin4u/agentic-core/pao";

const code = "nspk:agent:install-check-01:v1";
const { signer, publicKey } = newEd25519Signer("unset");
const jwk = createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" }).export({ format: "jwk" });
const kid = createHash("sha256").update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest("base64url");

const s = createStand();
const d = s.admit({ agent_code: code, class: "BUYER", model: "install-check", runtime: "node", alg: "ed25519", public_key: publicKey }, "install-check-operator");
if (!d.admitted) throw new Error("допуск не прошёл: " + JSON.stringify(d));
const baseUrl = await s.listen();
try {
  const self = await new PaoClient({ baseUrl, agentCode: code, signer: { ...signer, kid }, maxAttempts: 1 }).call("GET /pao/v1/agent", {});
  if (self.agent_code !== code || self.keys?.[0]?.kid !== kid) throw new Error("неверный ответ: " + JSON.stringify(self));
  const health = await (await fetch(baseUrl + "/health")).json();
  if (health.env !== "dev") throw new Error("среда стенда не dev: " + JSON.stringify(health));
  if ("store" in s || "verifier" in s) throw new Error("стенд отдаёт хранилище или проверку подписи (РП25)");
  console.log("стенд из установки: GET /pao/v1/agent 200, kid совпал, среда dev");
  // PS-12: фикстуры и витрины — из того же пакета, один источник.
  const m = createMerchants(s);
  try {
    const shopsUrl = await m.listen();
    const shops = (await (await fetch(shopsUrl + "/v1/shops")).json()).shops.map((x) => x.id);
    if (JSON.stringify(shops) !== JSON.stringify(MERCHANT_FIXTURES.map((x) => x.id))) throw new Error("витрины ≠ фикстуры: " + shops);
    if (!AGENT_FIXTURES.length) throw new Error("нет фикстур агентов");
    console.log("витрины из установки: GET /v1/shops 200, совпадают с фикстурами");
  } finally {
    await m.close();
  }
} finally {
  await s.close();
}
`,
  );
  execFileSync("node", ["check.mjs"], { cwd: app, stdio: "inherit" });
  console.log(`проверка установки (${mode}${ref ? " " + ref : ""}) — успешно`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
