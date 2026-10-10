#!/usr/bin/env python3
"""Хук PreToolUse: блокирует опасные действия до их выполнения.

Код выхода 2 блокирует вызов; текст из stderr видит Claude.
Что блокируется:
  1. Запись в защищённые пути: docs/reference/**, .env*, *.pem, *.key, сам .claude/hooks/**.
     Для Bash проверяются именно ЦЕЛИ записи (>, >>, tee, sed -i, cp/mv — последний аргумент,
     rm, truncate), а не любое упоминание пути — чтение разрешено.
  2. Чтение .env и ключей через Read и через Bash (cat/less/head/tail/grep/source и т. п.).
  3. Содержимое с ключом API (sk-ant-), приватным ключом PEM или номером карты (проверка Луна).
  4. git push — только в ветки task/* (без --force, --tags, удаления); создание PR разрешено; слияние PR — владелец.
"""
import json, re, shlex, sys, os

PROTECTED_WRITE = [
    re.compile(r"(^|/)docs/reference(/|$)"),
    re.compile(r"(^|/)\.env(\.|$)"),
    re.compile(r"\.(pem|key)$"),
    re.compile(r"(^|/)\.claude/hooks(/|$)"),
]
ENV_EXAMPLE = re.compile(r"(^|/)\.env\.example$")
SECRET_READ = [re.compile(r"(^|/)\.env(\.|$)"), re.compile(r"\.(pem|key)$")]
READ_CMDS = {"cat", "less", "more", "head", "tail", "grep", "egrep", "rg", "awk", "sed", "source", ".", "strings", "xxd", "od", "base64", "cp", "open"}
API_KEY = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
DIGITS = re.compile(r"(?<![\w-])(?:\d[ -]?){15,19}(?![\w-])")


def luhn(num: str) -> bool:
    d = [int(c) for c in num][::-1]
    s = 0
    for i, x in enumerate(d):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def has_card(text: str) -> bool:
    for m in DIGITS.finditer(text or ""):
        n = re.sub(r"[ -]", "", m.group(0))
        if 15 <= len(n) <= 19 and len(set(n)) > 1 and luhn(n):
            return True
    return False


def rel(p: str) -> str:
    root = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    p = p.strip().strip('"').strip("'")
    if p.startswith(root):
        p = p[len(root):].lstrip("/")
    return p


def is_protected_write(p: str) -> bool:
    p = rel(p)
    if ENV_EXAMPLE.search(p):
        return False
    return any(r.search(p) for r in PROTECTED_WRITE)


def is_secret_read(p: str) -> bool:
    p = rel(p)
    if ENV_EXAMPLE.search(p):
        return False
    return any(r.search(p) for r in SECRET_READ)


def block(msg: str):
    sys.stderr.write("БЛОК guard.py: " + msg + "\n")
    sys.exit(2)


def check_content(text: str, where: str):
    if API_KEY.search(text or ""):
        block(f"{where}: найден ключ API (sk-ant-). Ключи — только в .env.")
    if PEM.search(text or ""):
        block(f"{where}: найден приватный ключ. Ключи генерируются в тестах во временный каталог.")
    if has_card(text):
        block(f"{where}: похоже на номер карты (проходит проверку Луна). Используйте instrument_token вида tok_... (инвариант 1).")


def bash_write_targets(cmd: str):
    targets = []
    for segment in re.split(r"&&|\|\||;|\|", cmd):
        try:
            tok = shlex.split(segment, posix=True)
        except ValueError:
            tok = segment.split()
        if not tok:
            continue
        for i, t in enumerate(tok):
            if t in (">", ">>", "1>", "2>", "&>") and i + 1 < len(tok):
                targets.append(tok[i + 1])
            elif re.match(r"^\d?>>?\S+", t):
                targets.append(re.sub(r"^\d?>>?", "", t))
        head = tok[0]
        args = [a for a in tok[1:] if not a.startswith("-")]
        if head == "tee":
            targets += args
        elif head in ("cp", "mv", "install", "ln", "rsync") and args:
            targets.append(args[-1])
        elif head in ("rm", "truncate", "touch", "chmod", "unlink") :
            targets += args
        elif head == "sed" and any(a.startswith("-i") for a in tok[1:]):
            targets += args[1:] if args else []
        elif head in ("perl",) and any(a.startswith("-i") or a == "-pi" for a in tok[1:]):
            targets += args[1:] if args else []
    return targets


def bash_read_targets(cmd: str):
    reads = []
    for segment in re.split(r"&&|\|\||;|\|", cmd):
        try:
            tok = shlex.split(segment, posix=True)
        except ValueError:
            tok = segment.split()
        if not tok:
            continue
        if tok[0] in READ_CMDS:
            reads += [a for a in tok[1:] if not a.startswith("-")]
        for i, t in enumerate(tok):
            if t == "<" and i + 1 < len(tok):
                reads.append(tok[i + 1])
    return reads


# --- push разрешён только в ветки task/* (решение владельца 09.10.2026) ---
TASK_RE = re.compile(r"^(refs/heads/)?task/[A-Za-z0-9._/-]+$")
FORBIDDEN_PUSH_FLAGS = {"-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror", "--all",
                        "--tags", "--follow-tags", "--delete", "-d", "--prune", "--no-verify"}


def current_branch() -> str:
    import subprocess
    try:
        out = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True,
                             cwd=os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd()), timeout=5)
        return out.stdout.strip()
    except Exception:
        return ""


def check_git_push(cmd: str):
    """None — push разрешён; иначе текст причины отказа."""
    for segment in re.split(r"&&|\|\||;|\|", cmd):
        if not re.search(r"\bgit\b.*\bpush\b", segment):
            continue
        try:
            tok = shlex.split(segment, posix=True)
        except ValueError:
            return "Не удалось разобрать команду git push."
        if "git" not in tok or "push" not in tok:
            continue
        raw = tok[tok.index("push") + 1:]
        # перенаправления вывода (2>&1, >/dev/null, > файл) — не аргументы git push
        rest, skip = [], False
        for t in raw:
            if skip:
                skip = False
                continue
            if re.match(r"^(\d*|&)[<>]+&?\d*$", t):
                skip = not re.search(r"&\d*$", t)
                continue
            if re.match(r"^(\d*|&)[<>]", t):
                continue
            rest.append(t)
        for t in rest:
            if t in FORBIDDEN_PUSH_FLAGS or t.startswith("--force") or t.startswith("--push-option") or t.startswith("-o"):
                return f"git push с флагом {t} запрещён: только обычный push в ветки task/*."
        args = [t for t in rest if not t.startswith("-")]
        refspecs = args[1:] if args else []
        if not refspecs:
            br = current_branch()
            if not TASK_RE.match(br):
                return f"git push без указания ветки разрешён только из веток task/* (сейчас: {br or 'неизвестно'})."
            continue
        for r in refspecs:
            if r.startswith("+"):
                return "Принудительный push (+refspec) запрещён."
            if ":" in r:
                src, dst = r.split(":", 1)
                if not src:
                    return "Удаление ветки через push запрещено."
            else:
                src, dst = r, r
            if dst == "HEAD":
                dst = current_branch()
            if src == "HEAD" and ":" not in r:
                dst = current_branch()
            if not TASK_RE.match(dst):
                return f"git push разрешён только в ветки task/* (цель: {dst}). main, теги и другие ветки — владелец."
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    tool = data.get("tool_name", "")
    ti = data.get("tool_input", {}) or {}

    if tool in ("Write", "Edit", "MultiEdit"):
        path = ti.get("file_path", "")
        if is_protected_write(path):
            block(f"запись в защищённый путь {rel(path)}. docs/reference — только чтение; .env и ключи — вне репозитория; хуки меняет владелец.")
        parts = [ti.get("content", ""), ti.get("new_string", "")]
        for e in ti.get("edits", []) or []:
            parts.append(e.get("new_string", ""))
        check_content("\n".join(p for p in parts if p), rel(path))

    elif tool == "Read":
        path = ti.get("file_path", "")
        if is_secret_read(path):
            block(f"чтение {rel(path)} запрещено: секреты не попадают в контекст.")

    elif tool == "Bash":
        cmd = ti.get("command", "")
        if re.search(r"\bgh\s+pr\s+merge\b", cmd):
            block("Слияние PR делает владелец.")
        err = check_git_push(cmd)
        if err:
            block(err)
        for t in bash_write_targets(cmd):
            if is_protected_write(t):
                block(f"команда пишет в защищённый путь {rel(t)}.")
        for t in bash_read_targets(cmd):
            if is_secret_read(t):
                block(f"команда читает секрет {rel(t)}.")
        check_content(cmd, "команда")
    sys.exit(0)


if __name__ == "__main__":
    main()
