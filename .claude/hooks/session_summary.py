#!/usr/bin/env python3
"""Хук Stop: сводка текущей сессии из .claude/hooks.log в .claude/session-summary.md.
Используется командой /finish для учёта сделанного объёма.
Изменённые файлы — git diff --name-only от коммита начала сессии (head первой записи) и новые
неотслеживаемые файлы; разбор команд Bash для списка не используется (расхождение №11 agentic-core).
Без head или без git — по записям журнала, как раньше."""
import json, os, sys, collections, subprocess

def git_lines(root, *args):
    r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return [l for l in r.stdout.splitlines() if l]

def git_files(root, base):
    files = set(git_lines(root, "diff", "--name-only", base))
    files.update(git_lines(root, "ls-files", "--others", "--exclude-standard"))
    return sorted(files)

def main():
    try:
        d = json.load(sys.stdin)
        sid = d.get("session_id", "")
    except Exception:
        sid = ""
    root = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    log = os.path.join(root, ".claude", "hooks.log")
    if not os.path.exists(log):
        return
    recs = []
    with open(log, encoding="utf-8") as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if not sid or r.get("session") == sid:
                recs.append(r)
    if not recs:
        return
    kinds = collections.Counter(k for r in recs for k in r.get("kinds", [r.get("kind")]))
    base = next((r["head"] for r in recs if r.get("head")), "")
    listed = None
    if base:
        try:
            listed = git_files(root, base)
            source = f"`git diff --name-only {base[:7]}` и новые неотслеживаемые файлы"
        except Exception:
            listed = None
    if listed is None:
        files = collections.Counter()
        for r in recs:
            for p in r.get("files", []):
                if p:
                    files[p] += 1
        source = "записи журнала (нет коммита начала сессии или git недоступен)"
    out = ["# Сводка сессии", "", f"Сессия: `{sid or 'все записи'}`", f"Начало: {recs[0]['t']} · конец: {recs[-1]['t']}", "",
           f"Правок через редактор: {kinds.get('edit',0)} · через Bash: {kinds.get('bash-edit',0)} · запусков тестов: {kinds.get('test',0)} · коммитов: {kinds.get('commit',0)}", "",
           "## Изменённые файлы", "", f"Источник: {source}", ""]
    if listed is not None:
        out += [f"- `{p}`" for p in listed]
    else:
        out += [f"- `{p}` — {n}" for p, n in sorted(files.items())]
    with open(os.path.join(root, ".claude", "session-summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

if __name__ == "__main__":
    main()
