#!/usr/bin/env python3
"""Хук Stop: сводка текущей сессии из .claude/hooks.log в .claude/session-summary.md.
Используется командой /finish для учёта сделанного объёма."""
import json, os, sys, collections

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
    files = collections.Counter()
    kinds = collections.Counter(k for r in recs for k in r.get("kinds", [r.get("kind")]))
    for r in recs:
        for p in r.get("files", []):
            if p:
                files[p] += 1
    out = ["# Сводка сессии", "", f"Сессия: `{sid or 'все записи'}`", f"Начало: {recs[0]['t']} · конец: {recs[-1]['t']}", "",
           f"Правок через редактор: {kinds.get('edit',0)} · через Bash: {kinds.get('bash-edit',0)} · запусков тестов: {kinds.get('test',0)} · коммитов: {kinds.get('commit',0)}", "",
           "## Изменённые файлы", ""]
    out += [f"- `{p}` — {n}" for p, n in sorted(files.items())]
    with open(os.path.join(root, ".claude", "session-summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

if __name__ == "__main__":
    main()
