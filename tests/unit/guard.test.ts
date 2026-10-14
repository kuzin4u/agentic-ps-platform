// Хук PreToolUse .claude/hooks/guard.py: push только в ветки task/* (служебная 14.10, часть 2, К1.1; перенос К2.1 агента и П1 agentic-core).
// Текст внутри heredoc — данные, а не команда: описание PR или комментарий с «git push origin main» не блокируется.
// Настоящий push в main блокируется и рядом с heredoc. Тело heredoc с незакавыченным ограничителем, где есть
// подстановка команды $(…) или `…`, исполняется оболочкой — его хук проверяет как команду.
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const GUARD = join(process.cwd(), ".claude/hooks/guard.py");

function guard(command: string): { status: number | null; stderr: string } {
  const r = spawnSync("python3", [GUARD], {
    input: JSON.stringify({ tool_name: "Bash", tool_input: { command } }),
    encoding: "utf8",
    env: { ...process.env, CLAUDE_PROJECT_DIR: process.cwd() },
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
