#!/usr/bin/env python3
"""Хук PostToolUse: одна строка JSON на каждое изменение в .claude/hooks.log.
Учитываются правки через Write/Edit/MultiEdit и через Bash (cp, mv, sed -i, cat >>, tee, rm и т. п.)."""
import json, os, sys, datetime, re
sys.path.insert(0, os.path.dirname(__file__))
try:
    from guard import bash_write_targets, rel
except Exception:
    bash_write_targets = lambda c: []
    rel = lambda p: p

def main():
    try:
        d = json.load(sys.stdin)
    except Exception:
        return
    tool = d.get("tool_name", "")
    ti = d.get("tool_input", {}) or {}
    rec = {"t": datetime.datetime.now().isoformat(timespec="seconds"), "session": d.get("session_id", ""), "tool": tool}
    if tool in ("Write", "Edit", "MultiEdit"):
        rec["kinds"] = ["edit"]
        rec["files"] = [rel(ti.get("file_path", ""))]
    elif tool == "Bash":
        cmd = ti.get("command", "")
        targets = [rel(t) for t in bash_write_targets(cmd)]
        kinds = ["bash-edit"] if targets else ["bash"]
        if re.search(r"\b(vitest|npm (run )?test)\b", cmd):
            kinds.append("test")
        if re.search(r"\bgit commit\b", cmd):
            kinds.append("commit")
        rec["kinds"] = kinds
        rec["files"] = targets
        rec["cmd"] = cmd[:200]
    else:
        return
    root = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    with open(os.path.join(root, ".claude", "hooks.log"), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    main()
