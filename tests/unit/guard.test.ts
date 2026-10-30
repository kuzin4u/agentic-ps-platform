// Хук PreToolUse .claude/hooks/guard.py: push только в ветки task/* (служебная 14.10, часть 2, К1.1; перенос К2.1 агента и П1 agentic-core).
// Текст внутри heredoc — данные, а не команда: описание PR или комментарий с «git push origin main» не блокируется.
// Настоящий push в main блокируется и рядом с heredoc. Тело heredoc с незакавыченным ограничителем, где есть
// подстановка команды $(…) или `…`, исполняется оболочкой — его хук проверяет как команду.
// С1 (РП68 п. 1): полный прогон — только при нагрузке < 10 и без чужого vitest; нагрузку и pgrep тест подменяет
// переменными GUARD_TEST_LOADAVG и GUARD_TEST_VITEST. GUARD_PATH — путь к проверяемой копии стража (поломки, РП68 п. 5).
// С2 (РП68 п. 2): >>, tee -a, sed -i, perl -i по файлам репозитория и памяти Claude Code — блок; память — под HOME теста.
// С3 (РП68 п. 3): snap / verify и порядок поломок — во временном каталоге проекта (CLAUDE_PROJECT_DIR теста).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const GUARD = process.env.GUARD_PATH ?? join(process.cwd(), ".claude/hooks/guard.py");

function guard(command: string, env: Record<string, string> = {}, cwd?: string): { status: number | null; stderr: string } {
  const r = spawnSync("python3", [GUARD], {
    input: JSON.stringify({ tool_name: "Bash", tool_input: { command }, ...(cwd ? { cwd } : {}) }),
    encoding: "utf8",
    env: { ...process.env, CLAUDE_PROJECT_DIR: process.cwd(), ...env },
  });
  return { status: r.status, stderr: r.stderr };
}

const ALLOWED: [string, string][] = [
  ["тело heredoc в кавычках", "cat > /tmp/pr.md <<'EOF'\nСлияние: git push origin main — владелец.\nEOF"],
  ["тело heredoc без кавычек", "cat > /tmp/pr.md <<EOF\ngit push origin main\nEOF"],
  ["ограничитель в двойных кавычках", 'cat > /tmp/pr.md <<"END"\ngit push --force origin main\nEND'],
  ["heredoc с <<- и табуляцией", "cat > /tmp/pr.md <<-EOF\n\tgit push origin HEAD:main\n\tEOF"],
  ["тело комментария PR", "gh pr comment 24 --body-file - <<'EOF'\nClaude Code: push в main блокирует guard.py (git push origin main).\nEOF"],
  ["сообщение коммита через $(cat <<'EOF')", "git commit -m \"$(cat <<'EOF'\nК2.1: push в main (git push origin main) — владелец\nEOF\n)\""],
  ["упоминание в сообщении коммита", 'git commit -m "guard: git push origin main блокируется"'],
  ["два heredoc подряд", "cat > /tmp/a.md <<'A'\ngit push origin main\nA\ncat > /tmp/b.md <<'B'\ngit push --tags\nB"],
  ["push в task/* после heredoc", "cat > /tmp/pr.md <<'EOF'\ngit push origin main\nEOF\ngit push origin task/service-1410"],
  ["обычный push в task/*", "git push origin task/service-1410"],
];

const BLOCKED: [string, string][] = [
  ["push в main", "git push origin main"],
  ["push HEAD:main", "git push origin HEAD:main"],
  ["push в main после heredoc", "cat > /tmp/pr.md <<'EOF'\nтекст\nEOF\ngit push origin main"],
  ["push в main в строке heredoc", "cat > /tmp/pr.md <<'EOF' && git push origin main\nтекст\nEOF"],
  ["push в main, читающий heredoc", "git push origin main <<'EOF'\nтекст\nEOF"],
  ["push в main через && после heredoc", "cat > /tmp/pr.md <<'EOF'\nтекст\nEOF\ntrue && git push origin main"],
  ["$(…) в теле heredoc без кавычек", "cat > /tmp/pr.md <<EOF\n$(git push origin main)\nEOF"],
  ["`…` в теле heredoc без кавычек", "cat > /tmp/pr.md <<EOF\n`git push origin main`\nEOF"],
  ["$(…) без heredoc", 'x="$(git push origin main)"'],
  ["незакрытый heredoc", "cat > /tmp/pr.md <<'EOF'\ngit push origin main"],
  ["принудительный push в task/*", "git push --force origin task/service-1410"],
];

describe("guard.py: push только в task/*, heredoc — данные", () => {
  it.each(ALLOWED)("пропускает: %s", (_name, command) => {
    const r = guard(command);
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
  });

  it.each(BLOCKED)("блокирует: %s", (_name, command) => {
    const r = guard(command);
    expect(r.stderr).toContain("БЛОК guard.py");
    expect(r.status).toBe(2);
  });
});

const CALM = { GUARD_TEST_LOADAVG: "2.5", GUARD_TEST_VITEST: "0" };
const BUSY = { GUARD_TEST_LOADAVG: "17.3", GUARD_TEST_VITEST: "0" };

const FULL_RUNS: [string, string][] = [
  ["npm test", "npm test"],
  ["npm run test", "npm run test"],
  ["npm t", "npm t"],
  ["npm test с флагом", "npm test -- --reporter=dot"],
  ["npm test с выводом в файл", "npm test > /tmp/test.log 2>&1"],
  ["npx vitest run", "npx vitest run"],
  ["npx vitest без run", "npx vitest"],
  ["vitest из node_modules/.bin", "node_modules/.bin/vitest run"],
  ["с присваиванием перед командой", "CI=1 npm test"],
  ["после &&", "uptime && npm test"],
  ["в подстановке $(…)", 'x="$(npm test)"'],
  ["фильтр по имени, а не путь", "npx vitest run guard"],
];

const FILE_RUNS: [string, string][] = [
  ["npx vitest run файл", "npx vitest run tests/unit/guard.test.ts"],
  ["npm test -- файл", "npm test -- tests/unit/guard.test.ts"],
  ["каталог", "npx vitest run tests/unit/"],
  ["другой скрипт npm", "npm run test:install -- --pack"],
  ["упоминание в сообщении коммита", 'git commit -m "К1.1: npm test зелёный"'],
  ["в теле heredoc", "cat > /tmp/pr.md <<'EOF'\nnpm test\nEOF"],
];

describe("guard.py С1: полный прогон — нагрузка < 10 и без чужого vitest", () => {
  it.each(FULL_RUNS)("пропускает при нагрузке < 10: %s", (_name, command) => {
    const r = guard(command, CALM);
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
  });

  it.each(FULL_RUNS)("блокирует при нагрузке ≥ 10: %s", (_name, command) => {
    const r = guard(command, BUSY);
    expect(r.stderr).toContain("БЛОК guard.py");
    expect(r.stderr).toContain("по файлам");
    expect(r.status).toBe(2);
  });

  it.each(FILE_RUNS)("не ограничивает прогон по файлам: %s", (_name, command) => {
    const r = guard(command, { GUARD_TEST_LOADAVG: "17.3", GUARD_TEST_VITEST: "1" });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
  });

  it("нагрузка ровно 10 — блок", () => {
    const r = guard("npm test", { GUARD_TEST_LOADAVG: "10", GUARD_TEST_VITEST: "0" });
    expect(r.status).toBe(2);
  });

  it("чужой vitest при малой нагрузке — блок", () => {
    const r = guard("npm test", { GUARD_TEST_LOADAVG: "2.5", GUARD_TEST_VITEST: "1" });
    expect(r.stderr).toContain("vitest/vitest.mjs");
    expect(r.status).toBe(2);
  });

  it("сбой проверки — блок (fail-closed)", () => {
    expect(guard("npm test", { GUARD_TEST_LOADAVG: "2.5", GUARD_TEST_VITEST: "error" }).status).toBe(2);
    expect(guard("npm test", { GUARD_TEST_LOADAVG: "нет", GUARD_TEST_VITEST: "0" }).status).toBe(2);
  });
});

const HOME = mkdtempSync(join(tmpdir(), "guard-home-"));
const MEMORY = join(HOME, ".claude/projects/-Users-x-repos-p/memory");
const REPO = process.cwd();

const APPEND_BLOCKED: [string, string][] = [
  ["printf >> в файл репозитория", "printf 'x\\n' >> tests/unit/a.test.ts"],
  ["cat >> с heredoc", "cat >> docs/core/STATUS.md <<'EOF'\nтекст\nEOF"],
  ["echo >>файл слитно", "echo x >>README.md"],
  ["echo x>>файл без пробелов", "echo x>>README.md"],
  ["2>> в файл репозитория", "ls 2>> err.log"],
  ["&>> в файл репозитория", "ls &>> out.log"],
  ["абсолютный путь в репозитории", `echo x >> ${REPO}/src/a.ts`],
  ["после &&", "true && printf x >> src/a.ts"],
  ["tee -a", "echo x | tee -a src/a.ts"],
  ["tee --append", "echo x | tee --append src/a.ts > /dev/null"],
  ["sed -i GNU", "sed -i 's/a/b/' src/a.ts"],
  ["sed -i '' BSD", "sed -i '' 's/a/b/' src/a.ts"],
  ["sed -i.bak -e", "sed -i.bak -e 's/a/b/' src/a.ts"],
  ["sed -E -i с абсолютным путём", `sed -E -i 's/a/b/' ${REPO}/src/a.ts`],
  ["perl -pi -e", "perl -pi -e 's/a/b/' src/a.ts"],
  ["память: >> через ~", "echo x >> ~/.claude/projects/-Users-x-repos-p/memory/MEMORY.md"],
  ["память: абсолютный путь", `printf x >> ${MEMORY}/note.md`],
  ["память: sed -i", `sed -i '' 's/a/b/' ${MEMORY}/MEMORY.md`],
  ["цель через переменную", 'echo x >> "$F"'],
  ["цель через $HOME", "sed -i 's/a/b/' $HOME/notes.md"],
  ["цель через подстановку", "echo x >> $(pwd)/a.md"],
  ["cd в каталог репозитория", "cd docs && echo x >> core/STATUS.md"],
  ["cd на переменную", 'cd "$D" && echo x >> f.md'],
  [">> без цели", "echo x >>"],
];

const APPEND_ALLOWED: [string, string][] = [
  [">> во временный каталог", "echo x >> /tmp/guard-test.log"],
  ["cd /tmp и относительный путь", "cd /tmp && echo x >> a.log"],
  ["tee -a во временный каталог", "echo x | tee -a /tmp/x.log"],
  ["sed -i '' во временном каталоге", "sed -i '' 's/a/b/' /tmp/x.txt"],
  ["sed без -i", "sed -n 's/a/b/p' src/a.ts"],
  ["перезапись > (не дописывание)", "echo x > /tmp/a.txt"],
  ["2>&1 и >> во временный каталог", "ls 2>&1 >> /tmp/a.log"],
  ["прогон с выводом в файл", "npx vitest run tests/unit/guard.test.ts > /tmp/a.log 2>&1"],
  [">> в кавычках — данные", 'git commit -m "К1.2: echo x >> README.md — блок"'],
  ["в теле heredoc — данные", "cat > /tmp/pr.md <<'EOF'\nprintf x >> src/a.ts\nEOF"],
  ["домашний каталог вне памяти", "echo x >> ~/notes.txt"],
  ["каталог проекта Claude вне memory", "echo x >> ~/.claude/projects/-Users-x-repos-p/other.md"],
];

describe("guard.py С2: >>, tee -a, sed -i, perl -i по репозиторию и памяти — блок", () => {
  it.each(APPEND_BLOCKED)("блокирует: %s", (_name, command) => {
    const r = guard(command, { HOME });
    expect(r.stderr).toContain("БЛОК guard.py");
    expect(r.status).toBe(2);
  });

  it.each(APPEND_ALLOWED)("пропускает: %s", (_name, command) => {
    const r = guard(command, { HOME });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
  });

  it("каталог из входа хука: из /tmp относительный путь пропускается, после cd на переменную — блок", () => {
    expect(guard("echo x >> f.md", { HOME }, "/tmp").status).toBe(0);
    expect(guard('cd "$D" && echo x >> f.md', { HOME }, "/tmp").status).toBe(2);
  });

  it("подсказка: репозиторий — инструментом Edit, переменная — путь буквально", () => {
    expect(guard("printf x >> src/a.ts", { HOME }).stderr).toContain("инструментом Edit");
    expect(guard('echo x >> "$F"', { HOME }).stderr).toContain("путь не вычислить");
  });
});

describe("guard.py С3: порядок поломок — снимок, поломка, прогон, откат, сверка", () => {
  function project() {
    const dir = mkdtempSync(join(tmpdir(), "guard-c3-"));
    mkdirSync(join(dir, ".git"));
    writeFileSync(join(dir, "a.ts"), "const a = 1;\n");
    writeFileSync(join(dir, "b.ts"), "const b = 2;\n");
    const env = { CLAUDE_PROJECT_DIR: dir };
    const cli = (cmd: string, file: string) =>
      spawnSync("python3", [GUARD, cmd, file], { encoding: "utf8", env: { ...process.env, ...env } });
    const tool = (tool_name: string, tool_input: Record<string, unknown>) => {
      const r = spawnSync("python3", [GUARD], {
        input: JSON.stringify({ tool_name, tool_input }),
        encoding: "utf8",
        env: { ...process.env, ...env },
      });
      return { status: r.status, stderr: r.stderr };
    };
    const edit = (file: string) => tool("Edit", { file_path: join(dir, file), old_string: "1", new_string: "3" });
    const bash = (command: string) => tool("Bash", { command });
    return { dir, state: join(dir, ".git/breakage.json"), cli, tool, edit, bash };
  }

  it("без снимка правки и коммит не ограничены", () => {
    const p = project();
    expect(p.edit("b.ts").status).toBe(0);
    expect(p.bash("git commit -F /tmp/msg.txt").status).toBe(0);
  });

  it("снимок открыт: другой файл и коммит — блок, снимаемый файл — правится", () => {
    const p = project();
    expect(p.cli("snap", join(p.dir, "a.ts")).status).toBe(0);
    expect(existsSync(p.state)).toBe(true);
    expect(p.edit("a.ts").status).toBe(0);
    const other = p.edit("b.ts");
    expect(other.status).toBe(2);
    expect(other.stderr).toContain("verify");
    expect(p.tool("Write", { file_path: join(p.dir, "c.ts"), content: "x" }).status).toBe(2);
    expect(p.tool("MultiEdit", { file_path: join(p.dir, "b.ts"), edits: [] }).status).toBe(2);
    expect(p.bash("git commit -F /tmp/msg.txt").stderr).toContain("коммит с непроверенным откатом");
    expect(p.bash("git add a.ts && git commit -F /tmp/msg.txt").status).toBe(2);
    expect(p.bash("git status -sb").status).toBe(0);
    expect(p.bash("cat > /tmp/pr.md <<'EOF'\ngit commit\nEOF").status).toBe(0);
    expect(p.tool("Read", { file_path: join(p.dir, "b.ts") }).status).toBe(0);
  });

  it("второй снимок — отказ, пока первый не сверен", () => {
    const p = project();
    expect(p.cli("snap", join(p.dir, "a.ts")).status).toBe(0);
    const again = p.cli("snap", join(p.dir, "b.ts"));
    expect(again.status).toBe(1);
    expect(again.stderr).toContain("снимок уже открыт");
  });

  it("откат не точный — снимок остаётся, точный — закрывается, правки снова открыты", () => {
    const p = project();
    const a = join(p.dir, "a.ts");
    expect(p.cli("snap", a).status).toBe(0);
    writeFileSync(a, "const a = 0; // поломка\n");
    const bad = p.cli("verify", a);
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain("откат не точный");
    expect(existsSync(p.state)).toBe(true);
    expect(p.edit("b.ts").status).toBe(2);
    writeFileSync(a, "const a = 1;\n");
    expect(p.cli("verify", join(p.dir, "b.ts")).status).toBe(1);
    const ok = p.cli("verify", a);
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain("откат точный");
    expect(existsSync(p.state)).toBe(false);
    expect(p.edit("b.ts").status).toBe(0);
    expect(p.bash("git commit -F /tmp/msg.txt").status).toBe(0);
  });

  it("verify без снимка — отказ", () => {
    const p = project();
    expect(p.cli("verify", join(p.dir, "a.ts")).status).toBe(1);
  });

  it("файл состояния не читается — правки, коммит и snap закрыты (fail-closed)", () => {
    const p = project();
    writeFileSync(p.state, "{не json");
    expect(p.edit("a.ts").status).toBe(2);
    expect(p.bash("git commit -F /tmp/msg.txt").status).toBe(2);
    expect(p.cli("snap", join(p.dir, "a.ts")).status).toBe(2);
  });

  it("файл состояния руками не меняется", () => {
    const p = project();
    expect(p.cli("snap", join(p.dir, "a.ts")).status).toBe(0);
    expect(p.bash(`rm ${p.state}`).status).toBe(2);
    expect(p.bash(`echo '{}' > ${p.state}`).status).toBe(2);
    const fresh = project();
    expect(fresh.tool("Write", { file_path: fresh.state, content: "{}" }).status).toBe(2);
  });
});
