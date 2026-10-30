// Порт оператора приёмки песочницы (SANDBOX-ACC К1.1, вариант В): удалённые команды по ssh — из безопасных частей,
// программа — во временном каталоге пользователя сервиса и удаляется в close(); отказы operator.mjs — кодом, без текста.
// Допуск и отзыв на PostgreSQL — в tests/unit/acceptance.test.ts (CI).
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  OPERATOR_PROGRAM,
  OperatorError,
  parseReply,
  spawnExec,
  sshOperator,
  type Exec,
  type ExecResult,
} from "../../scripts/acceptance/operator.js";

const ok = (stdout = ""): ExecResult => ({ code: 0, stdout, stderr: "" });

/** ssh-заглушка: запись вызовов, ответ — по удалённой команде. */
function fakeSsh(answer: (remote: string, input?: string) => ExecResult) {
  const calls: { args: readonly string[]; input?: string }[] = [];
  const exec: Exec = async (cmd, args, input) => {
    expect(cmd).toBe("ssh");
    calls.push({ args, input });
    return answer(args[args.length - 1] as string, input);
  };
  return { calls, exec };
}

const opts = { target: "owner@vps.example", root: "/opt/agentic-ps-platform", envFile: "/etc/agentic-platform/env", unit: "agentic-platform", user: "agentic" };

describe("sshOperator — удалённые команды", () => {
  it("допуск: каталог пользователя сервиса, копия программы, запуск на dist установки; повтор — тот же каталог; close — удаление", async () => {
    const { calls, exec } = fakeSsh((remote) => {
      if (remote.endsWith("mktemp -d")) return ok("/tmp/tmp.AbC123\n");
      if (remote.includes(" node ")) return ok('{"admitted":true,"agent_code":"nspk:agent:acc-1:v1"}\n');
      return ok();
    });
    const op = sshOperator({ ...opts, exec, program: "// программа" });
    expect(await op.admit({ agent_code: "nspk:agent:acc-1:v1" })).toEqual({ admitted: true, agent_code: "nspk:agent:acc-1:v1" });
    await op.admit({ agent_code: "nspk:agent:acc-2:v1" });
    await op.close();
    await op.close();

    expect(calls.map((c) => c.args.slice(0, 4))).toEqual(Array(5).fill(["-o", "BatchMode=yes", "owner@vps.example", "--"]));
    expect(calls.map((c) => c.args[4])).toEqual([
      "sudo -n -u agentic mktemp -d",
      'sudo -n -u agentic sh -c "cat > /tmp/tmp.AbC123/operator.mjs"',
      "sudo -n -u agentic node /tmp/tmp.AbC123/operator.mjs /opt/agentic-ps-platform /etc/agentic-platform/env",
      "sudo -n -u agentic node /tmp/tmp.AbC123/operator.mjs /opt/agentic-ps-platform /etc/agentic-platform/env",
      "sudo -n -u agentic rm -rf /tmp/tmp.AbC123",
    ]);
    expect(calls[1]?.input).toBe("// программа");
    expect(JSON.parse(calls[2]?.input as string)).toEqual({ cmd: "admit", application: { agent_code: "nspk:agent:acc-1:v1" } });
  });

  it("программа по умолчанию — operator.mjs рядом с портом", async () => {
    const { calls, exec } = fakeSsh((remote) => (remote.endsWith("mktemp -d") ? ok("/tmp/d1\n") : ok('{"revoked":true}')));
    expect(await sshOperator({ ...opts, exec }).revoke("0a1b")).toBe(true);
    expect(calls[1]?.input).toContain("op-acceptance");
    expect(OPERATOR_PROGRAM.endsWith("scripts/acceptance/operator.mjs")).toBe(true);
    expect(JSON.parse(calls[2]?.input as string)).toEqual({ cmd: "revoke", serial: "0a1b" });
  });

  it.each([
    ["target", "vps; rm -rf /", "UNSAFE_TARGET"],
    ["root", "/opt/my platform", "UNSAFE_ROOT"],
    ["envFile", "/etc/env$(id)", "UNSAFE_ENV_FILE"],
    ["unit", "a`b`", "UNSAFE_UNIT"],
    ["user", "agentic&&x", "UNSAFE_USER"],
    ["target", "-F/tmp/evil_config", "UNSAFE_TARGET"],
    ["unit", "-Hroot@other", "UNSAFE_UNIT"],
    ["unit", "../etc/x", "UNSAFE_UNIT"],
  ])("небезопасный %s — отказ до ssh", (k, v, code) => {
    const { calls, exec } = fakeSsh(() => ok());
    expect(() => sshOperator({ ...opts, [k]: v, exec })).toThrow(new OperatorError("params", code));
    expect(calls).toHaveLength(0);
  });

  it("mktemp вернул не путь — отказ, программа не копируется", async () => {
    const { calls, exec } = fakeSsh(() => ok("tmp dir; x\n"));
    await expect(sshOperator({ ...opts, exec }).admit({})).rejects.toThrow(new OperatorError("mktemp", "EXIT_0"));
    expect(calls).toHaveLength(1);
  });

  it("журнал — по InvocationID текущего запуска; неизвестный — отказ; перезапуск — systemctl", async () => {
    const id = "0123456789abcdef0123456789abcdef";
    const { calls, exec } = fakeSsh((remote) => (remote.startsWith("systemctl show") ? ok(`${id}\n`) : ok('{"msg":"x"}\n')));
    const op = sshOperator({ ...opts, exec });
    expect(await op.journal()).toBe('{"msg":"x"}\n');
    await op.restart();
    expect(calls.map((c) => c.args[4])).toEqual([
      "systemctl show -p InvocationID --value agentic-platform",
      `journalctl _SYSTEMD_INVOCATION_ID=${id} -o cat --no-pager`,
      "sudo -n systemctl restart agentic-platform",
    ]);
    const bad = fakeSsh(() => ok("\n"));
    await expect(sshOperator({ ...opts, exec: bad.exec }).journal()).rejects.toThrow(new OperatorError("journal", "INVOCATION_UNKNOWN"));
    const down = fakeSsh(() => ({ code: 1, stdout: "", stderr: "" }));
    await expect(sshOperator({ ...opts, exec: down.exec }).restart()).rejects.toThrow(new OperatorError("restart", "EXIT_1"));
  });
});

describe("parseReply", () => {
  it("{ error } — код отказа; не JSON — код выхода; JSON при ненулевом выходе — код выхода", () => {
    expect(() => parseReply("admit", { code: 1, stdout: '{"error":"ENV_NOT_SANDBOX"}\n', stderr: "" })).toThrow(new OperatorError("admit", "ENV_NOT_SANDBOX"));
    expect(() => parseReply("admit", { code: 255, stdout: "", stderr: "ssh: connect" })).toThrow(new OperatorError("admit", "EXIT_255"));
    expect(() => parseReply("admit", { code: 3, stdout: '{"admitted":true}', stderr: "" })).toThrow(new OperatorError("admit", "EXIT_3"));
    expect(parseReply("admit", { code: 0, stdout: 'шум\n{"admitted":false,"reasons":["APPLICATION_INCOMPLETE"]}\n', stderr: "" })).toEqual({
      admitted: false,
      reasons: ["APPLICATION_INCOMPLETE"],
    });
  });
});

describe("operator.mjs — отказы до базы", () => {
  // Окружение — только заданное: PLATFORM_ENV и DATABASE_URL окна не протекают.
  const run = (args: string[], env: NodeJS.ProcessEnv) => spawnExec(process.execPath, [OPERATOR_PROGRAM, ...args], "{}", { PATH: process.env.PATH, ...env });

  it("без аргументов — USAGE; не sandbox — ENV_NOT_SANDBOX; нет файла окружения — ENV_FILE_ENOENT", async () => {
    expect(parseReplyCode(await run([], {}))).toBe("USAGE");
    expect(parseReplyCode(await run([process.cwd(), "-"], { PLATFORM_ENV: "dev" }))).toBe("ENV_NOT_SANDBOX");
    expect(parseReplyCode(await run([process.cwd(), "/nonexistent/env"], {}))).toBe("ENV_FILE_ENOENT");
  });

  it("EnvironmentFile: sandbox из файла (кавычки снимаются), без DATABASE_URL — DATABASE_URL_MISSING", async () => {
    const f = join(mkdtempSync(join(tmpdir(), "acc-env-")), "env");
    writeFileSync(f, '# комментарий\nPLATFORM_ENV="sandbox"\nPORT=8443\n');
    expect(parseReplyCode(await run([process.cwd(), f], {}))).toBe("DATABASE_URL_MISSING");
  });
});

describe("spawnExec — процесс не читает ввод (К1 сессии 59)", () => {
  // Путь SCHEMA_NOT_READY: operator.mjs выходит, не прочитав stdin; запись в закрытый канал — EPIPE.
  // Итог — код выхода и вывод процесса, не необработанная ошибка (CI PR #84, d495796).
  it("выход сразу при большом вводе — результат с кодом процесса", async () => {
    const big = "x".repeat(8 * 1024 * 1024);
    for (let i = 0; i < 5; i++) {
      const r = await spawnExec(process.execPath, ["-e", 'process.stdout.write("ушёл"); process.exit(3)'], big);
      expect(r).toEqual({ code: 3, stdout: "ушёл", stderr: "" });
    }
  });
});

function parseReplyCode(r: ExecResult): string {
  try {
    parseReply("t", r);
  } catch (e) {
    if (e instanceof OperatorError) return e.code;
  }
  return "NO_ERROR";
}
