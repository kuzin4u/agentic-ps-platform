// .claude/settings.json (РП68 п. 4, служебная SVC-58): заранее разрешено только чтение, изменяющие команды — с вопросом,
// слияние PR — запрет, auto mode выключен (disableAutoMode). Порядок Claude Code: deny → ask → allow, списки файлов
// настроек складываются — ask проектного файла перекрывает allow из settings.local.json. Страж guard.py подключён
// к PreToolUse. SETTINGS_PATH — путь к проверяемой копии (поломки, РП68 п. 5).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

type Hook = { matcher?: string; hooks: { type: string; command: string }[] };
type Settings = {
  disableAutoMode?: string;
  permissions: { allow: string[]; ask: string[]; deny: string[] };
  hooks: Record<string, Hook[]>;
};

const PATH = process.env.SETTINGS_PATH ?? join(process.cwd(), ".claude/settings.json");
const settings = JSON.parse(readFileSync(PATH, "utf8")) as Settings;
const { allow, ask, deny } = settings.permissions;

const READ_ONLY = [
  "Bash(git status)",
  "Bash(git status:*)",
  "Bash(git log)",
  "Bash(git log:*)",
  "Bash(git diff)",
  "Bash(git diff:*)",
  "Bash(git show)",
  "Bash(git show:*)",
  "Bash(gh pr checks:*)",
  "Bash(gh pr view:*)",
  "Bash(npm test)",
  "Bash(npm test:*)",
  "Bash(npx vitest run:*)",
];

const ASK = [
  "Bash(git commit:*)",
  "Bash(git push:*)",
  "Bash(git revert:*)",
  "Bash(gh pr create:*)",
  "Bash(git checkout:*)",
  "Bash(git restore:*)",
  "Bash(git reset:*)",
  "Bash(git pull:*)",
  "Bash(npm install:*)",
  "Bash(npm i:*)",
  "Bash(curl:*)",
  "Bash(wget:*)",
];

describe(".claude/settings.json: только чтение без вопроса, auto mode выключен", () => {
  it("auto mode выключен", () => {
    expect(settings.disableAutoMode).toBe("disable");
  });

  it("allow — ровно список только для чтения", () => {
    expect([...allow].sort()).toEqual([...READ_ONLY].sort());
  });

  it.each(ASK)("ask: %s", (rule) => {
    expect(ask).toContain(rule);
  });

  it("слияние PR — запрет", () => {
    expect(deny).toContain("Bash(gh pr merge:*)");
  });

  it("изменяющие команды не разрешены заранее", () => {
    const changing = /^Bash\((git (commit|push|revert|checkout|restore|reset|pull|add|merge|rebase|tag)|gh pr (create|merge|ready|edit|comment)|npm (install|i|ci))\b/;
    expect(allow.filter((r) => changing.test(r))).toEqual([]);
    expect(allow.filter((r) => !r.startsWith("Bash("))).toEqual([]);
  });

  it("страж guard.py подключён к PreToolUse для Bash, Write, Edit, MultiEdit, Read", () => {
    const guard = (settings.hooks.PreToolUse ?? []).find((h) => h.hooks.some((x) => x.command.includes(".claude/hooks/guard.py")));
    expect(guard).toBeDefined();
    expect((guard?.matcher ?? "").split("|").sort()).toEqual(["Bash", "Edit", "MultiEdit", "Read", "Write"]);
  });
});
