// Тестовый банк-участник (Р-1031, Р-1040, К1.1 сессии 61): keygen — запись для participants.json, закрытый ключ PKCS8
// PEM 0600 без перезаписи и вне клона репозитория; ключи — только во временном каталоге.
import { spawnSync } from "node:child_process";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { keygen, ParticipantToolError, repoRootOf, revocationOrderOf } from "../../scripts/participant/keys.js";
import { loadTrustedParticipants, participantSigningInput, STAND_ISSUER_CODE } from "../../src/participants/trusted.js";
import { ED25519, parseKey } from "../../src/registry/keys.js";

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const MAIN = join(REPO, "scripts/participant/main.ts");
const IN_REPO_KEY = join(REPO, "scripts/participant/__never_written__.pem");

let dir: string;
let fakeRepo: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "participant-out-"));
  fakeRepo = mkdtempSync(join(tmpdir(), "participant-repo-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(fakeRepo, { recursive: true, force: true });
  rmSync(IN_REPO_KEY, { force: true });
});

const code = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof ParticipantToolError ? e.code : `other:${(e as Error).message}`;
  }
  return undefined;
};

/** Тело PEM без строк заголовка — то, чего не должно быть в выводе инструмента. */
const pemBody = (pem: string): string => pem.split("\n").filter((l) => l !== "" && !l.startsWith("-----")).join("");

describe("participant keygen", () => {
  it("запись — ровно поля файла, kid по RFC 7638, принимается рабочим сервером из файла (stand: false)", () => {
    const keyPath = join(dir, "bank.pem");
    const rec = keygen({ participant_code: "test-bank", keyPath, repoRoot: fakeRepo });
    expect(Object.keys(rec).sort()).toEqual(["alg", "kid", "participant_code", "public_key", "revocation_order"]);
    expect(rec.alg).toBe("ed25519");
    expect(rec.revocation_order).toBe(revocationOrderOf("test-bank"));
    expect(parseKey([ED25519], rec.alg, rec.public_key)?.kid).toBe(rec.kid);
    const file = join(dir, "participants.json");
    writeFileSync(file, JSON.stringify({ participants: [rec] }));
    const trusted = loadTrustedParticipants(file, { stand: false });
    expect(trusted.role("test-bank")).toBe("ISSUER");
    expect(trusted.revocationOrder()).toBe(rec.revocation_order);
  });

  it("закрытый ключ — PKCS8 PEM 0600, его открытая часть = записи, подпись решения проходит проверку сервера", () => {
    const keyPath = join(dir, "bank.pem");
    const rec = keygen({ participant_code: "test-bank", keyPath, repoRoot: fakeRepo });
    expect(statSync(keyPath).mode & 0o777).toBe(0o600);
    const pem = readFileSync(keyPath, "utf8");
    const priv = createPrivateKey(pem);
    expect(priv.asymmetricKeyType).toBe("ed25519");
    // PKCS8 PEM: повторный экспорт в PKCS8 PEM совпадает с файлом побайтно.
    expect(priv.export({ type: "pkcs8", format: "pem" })).toBe(pem);
    expect(createPublicKey(priv).export({ type: "spki", format: "der" }).toString("base64")).toBe(rec.public_key);
    const record = {
      participant_code: rec.participant_code,
      kid: rec.kid,
      mandate_id: "m-1",
      mandate_hash: "a".repeat(64),
      decision: "SIGN" as const,
      signature_type: "simple" as const,
      signature_ref: "ref-abc",
      token_consent: true,
      signed_at: "2026-10-31T12:00:00Z",
    };
    const sig = sign(null, participantSigningInput(record), priv).toString("base64url");
    const file = join(dir, "participants.json");
    writeFileSync(file, JSON.stringify({ participants: [rec] }));
    expect(loadTrustedParticipants(file, { stand: false }).verify(rec.participant_code, rec.kid, record, sig)).toBe(true);
  });

  it("без перезаписи: второй keygen по тому же пути — KEY_EXISTS, файл прежний", () => {
    const keyPath = join(dir, "bank.pem");
    keygen({ participant_code: "test-bank", keyPath, repoRoot: fakeRepo });
    const before = readFileSync(keyPath);
    expect(code(() => keygen({ participant_code: "test-bank", keyPath, repoRoot: fakeRepo }))).toBe("KEY_EXISTS");
    expect(readFileSync(keyPath).equals(before)).toBe(true);
  });

  it("путь внутри клона — KEY_PATH_IN_REPO, файла нет; в том числе в подкаталоге и через символьную ссылку", () => {
    mkdirSync(join(fakeRepo, "sub"));
    expect(code(() => keygen({ participant_code: "test-bank", keyPath: join(fakeRepo, "bank.pem"), repoRoot: fakeRepo }))).toBe("KEY_PATH_IN_REPO");
    expect(code(() => keygen({ participant_code: "test-bank", keyPath: join(fakeRepo, "sub", "bank.pem"), repoRoot: fakeRepo }))).toBe("KEY_PATH_IN_REPO");
    const link = join(dir, "link");
    symlinkSync(join(fakeRepo, "sub"), link);
    expect(code(() => keygen({ participant_code: "test-bank", keyPath: join(link, "bank.pem"), repoRoot: fakeRepo }))).toBe("KEY_PATH_IN_REPO");
    expect(existsSync(join(fakeRepo, "bank.pem")) || existsSync(join(fakeRepo, "sub", "bank.pem"))).toBe(false);
  });

  it("каталог с похожим именем рядом с клоном — не внутри (сравнение путей, а не строк)", () => {
    const sibling = `${fakeRepo}-keys`;
    mkdirSync(sibling);
    try {
      expect(code(() => keygen({ participant_code: "test-bank", keyPath: join(sibling, "bank.pem"), repoRoot: fakeRepo }))).toBeUndefined();
    } finally {
      rmSync(sibling, { recursive: true, force: true });
    }
  });

  it("каталога нет — KEY_DIR_MISSING", () => {
    expect(code(() => keygen({ participant_code: "test-bank", keyPath: join(dir, "no", "bank.pem"), repoRoot: fakeRepo }))).toBe("KEY_DIR_MISSING");
  });

  it("код эмулятора стенда и недопустимый код — CODE_INVALID до записи ключа", () => {
    const keyPath = join(dir, "bank.pem");
    expect(code(() => keygen({ participant_code: STAND_ISSUER_CODE, keyPath, repoRoot: fakeRepo }))).toBe("CODE_INVALID");
    expect(code(() => keygen({ participant_code: "bad code", keyPath, repoRoot: fakeRepo }))).toBe("CODE_INVALID");
    expect(existsSync(keyPath)).toBe(false);
  });

  it("корень git: у каталога инструмента — корень клона; вне git — REPO_ROOT_UNKNOWN", () => {
    expect(resolve(repoRootOf(join(REPO, "scripts/participant")))).toBe(REPO);
    expect(code(() => repoRootOf(dir))).toBe("REPO_ROOT_UNKNOWN");
  });
});

describe("participant CLI keygen", () => {
  const run = (...args: string[]) =>
    spawnSync(process.execPath, ["--import", "tsx", MAIN, ...args], { cwd: REPO, encoding: "utf8", timeout: 30_000 });

  it("вывод — открытая запись JSON, тела закрытого ключа в выводе нет; код 0", () => {
    const keyPath = join(dir, "bank.pem");
    const r = run("keygen", "--code", "test-bank", "--key", keyPath);
    expect(r.status).toBe(0);
    const body = pemBody(readFileSync(keyPath, "utf8"));
    expect(body.length).toBeGreaterThan(0);
    expect(r.stdout.replace(/\s/g, "")).not.toContain(body);
    expect(r.stderr.replace(/\s/g, "")).not.toContain(body);
    expect(r.stdout).not.toMatch(/-----BEGIN/);
    expect(JSON.parse(r.stdout).participant_code).toBe("test-bank");
  });

  it("путь в клоне репозитория — код 1, файла нет", () => {
    const r = run("keygen", "--code", "test-bank", "--key", IN_REPO_KEY);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/KEY_PATH_IN_REPO/);
    expect(existsSync(IN_REPO_KEY)).toBe(false);
  });

  it("нет параметров или неизвестная команда — код 2", () => {
    expect(run("keygen", "--code", "test-bank").status).toBe(2);
    expect(run("unknown").status).toBe(2);
  });
});
