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
     Тело heredoc — данные, не команда; подстановка $(…) и `…` проверяется как команда (К2.1, 14.10.2026).
  5. С1 — полный прогон тестов (npm test, npm run test, vitest без путей к файлам) — только при нагрузке
     за 1 мин < 10 и без чужого vitest (pgrep -f 'vitest/vitest.mjs'); сбой проверки — блок (РП68 п. 1).
  6. С2 — дописывание и правка на месте (>>, tee -a, sed -i, perl -i) в файлы репозитория и памяти Claude Code
     (~/.claude/projects/*/memory): правка — только инструментом Edit; цель через переменную или подстановку,
     относительный путь после cd на невычислимый каталог — блок (РП68 п. 2).
  7. С3 — порядок поломок «снимок sha256 → поломка → прогон → откат → сверка → следующая» (РП68 п. 3):
     python3 .claude/hooks/guard.py snap <файл> | verify <файл>; состояние — .git/breakage.json.
     При открытом снимке — блок Edit/Write другого файла и git commit; второй snap — отказ;
     verify закрывает снимок только при совпадении sha256; файл состояния руками не меняется.
"""
import json, re, shlex, sys, os

PROTECTED_WRITE = [
    re.compile(r"(^|/)docs/reference(/|$)"),
    re.compile(r"(^|/)\.env(\.|$)"),
    re.compile(r"\.(pem|key)$"),
    re.compile(r"(^|/)\.claude/hooks(/|$)"),
    re.compile(r"(^|/)\.git/breakage\.json$"),  # С3: снимок поломки закрывает только verify
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


# --- heredoc и подстановка команд (служебная сессия 14.10.2026, К2.1) ---
HEREDOC = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
SUBST = re.compile(r"\$\(|`")


def strip_heredocs(cmd: str) -> str:
    """Убирает тела heredoc: это данные, а не команда.

    Тело с незакавыченным ограничителем, где есть $(…) или `…`, оболочка исполняет — оно остаётся.
    Незакрытый heredoc не убирается (fail-closed).
    """
    lines = cmd.split("\n")
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in HEREDOC.finditer(line):
            dash, quote, word = m.group(1), m.group(2), m.group(3)
            j = i
            while j < len(lines) and (lines[j].lstrip("\t") if dash else lines[j]) != word:
                j += 1
            if j == len(lines):
                return cmd
            body = lines[i:j]
            if not quote and any(SUBST.search(b) for b in body):
                out += body
            i = j + 1
    return "\n".join(out)


def command_segments(cmd: str):
    """Сегменты команды: разделители оболочки, перевод строки и начало подстановки $(…) или `…`."""
    text = SUBST.sub("\n", strip_heredocs(cmd))
    return [s for s in re.split(r"&&|\|\||;|\||\n", text) if s.strip()]


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
    for segment in command_segments(cmd):
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


# --- С1: полный прогон только при нагрузке < 10 и без чужого vitest (РП68 п. 1, Р-806, Р-832) ---
LOAD_MAX = 10.0
VITEST_PROC = "vitest/vitest.mjs"
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
REDIRECT = re.compile(r"^(\d*|&)[<>]")


def test_file_arg(a: str) -> bool:
    """Аргумент — путь к файлу или каталогу тестов, а не имя скрипта или значение флага."""
    return "/" in a or ".test." in a or a.endswith((".ts", ".mts", ".js", ".mjs"))


def is_full_test_run(segment: str) -> bool:
    segment = re.sub(r"[)`]", " ", segment)  # хвост подстановки $(…) или `…` — не часть аргумента
    try:
        tok = shlex.split(segment, posix=True)
    except ValueError:
        tok = segment.split()
    # перенаправления (> файл, 2>&1) и присваивания перед командой — не аргументы
    clean, skip = [], False
    for t in tok:
        if skip:
            skip = False
            continue
        if REDIRECT.match(t):
            skip = re.fullmatch(r"(\d*|&)[<>]+", t) is not None
            continue
        clean.append(t)
    while clean and ENV_ASSIGN.match(clean[0]):
        clean = clean[1:]
    if not clean:
        return False
    if clean[0] == "npm":
        rest = clean[1:]
        if rest[:1] in (["test"], ["t"]):
            args = rest[1:]
        elif rest[:2] == ["run", "test"]:
            args = rest[2:]
        else:
            return False
    elif clean[0] == "npx" and clean[1:2] == ["vitest"]:
        args = clean[2:]
    elif os.path.basename(clean[0]) == "vitest":
        args = clean[1:]
    else:
        return False
    return not any(test_file_arg(a) for a in args if not a.startswith("-"))


def load_1min() -> float:
    forced = os.environ.get("GUARD_TEST_LOADAVG")  # только для тестов стража
    if forced is not None:
        return float(forced)
    return os.getloadavg()[0]


def vitest_running() -> bool:
    forced = os.environ.get("GUARD_TEST_VITEST")  # только для тестов стража: 0, 1 или error
    if forced is not None:
        if forced == "error":
            raise OSError("pgrep")
        return forced == "1"
    import subprocess
    r = subprocess.run(["pgrep", "-f", VITEST_PROC], capture_output=True, text=True, timeout=5)
    if r.returncode not in (0, 1):
        raise OSError("pgrep")
    return r.returncode == 0


def check_full_test_run(cmd: str):
    """None — прогон разрешён; иначе текст причины отказа."""
    if not any(is_full_test_run(s) for s in command_segments(cmd)):
        return None
    hint = "запустите по файлам (npx vitest run tests/…) или проверьте зелёный CI на голове PR"
    try:
        load = load_1min()
        busy = vitest_running()
    except Exception:
        return f"полный прогон: не удалось проверить нагрузку или чужой vitest — {hint}."
    if load >= LOAD_MAX:
        return f"полный прогон при нагрузке {load:.2f} (нужно < {LOAD_MAX:.0f}) — {hint}."
    if busy:
        return f"полный прогон при запущенном vitest ({VITEST_PROC}) — {hint}."
    return None


# --- С2: >>, tee -a, sed -i, perl -i по файлам репозитория и памяти — блок (РП68 п. 2, Р-651, Р-761) ---
UNRESOLVED = re.compile(r"[$`*?\[{]")
MEMORY_REL = re.compile(r"^[^/]+/memory(/|$)")


def shell_tokens(segment: str):
    """Токены с операторами перенаправления отдельно (a>>f → a, >>, f); строка в кавычках — один токен."""
    lex = shlex.shlex(segment, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return segment.split()


def append_targets(tok):
    """Цели дописывания и правки на месте в одном сегменте команды."""
    targets, words, i = [], [], 0
    while i < len(tok):
        t = tok[i]
        if re.fullmatch(r"[<>&|]+", t):
            nxt = tok[i + 1] if i + 1 < len(tok) else None
            if ">>" in t:
                targets.append(nxt if nxt is not None else "$")  # цель не видна — fail-closed
            if words and words[-1].isdigit():
                words.pop()  # номер дескриптора перед оператором (2>>, 2>)
            # цель перенаправления (файл, дескриптор в 2>&1) — не аргумент команды; & — фоновый запуск
            i += 1 if nxt is None or t in ("&", "|", "|&") else 2
            continue
        words.append(t)
        i += 1
    if not words:
        return targets
    head = os.path.basename(words[0])
    flags = [a for a in words[1:] if a.startswith("-")]
    args = [a for a in words[1:] if a and not a.startswith("-")]  # '' — суффикс BSD sed -i ''
    if head == "tee" and any(f in ("-a", "--append") or (re.match(r"^-[a-z]+$", f) and "a" in f) for f in flags):
        targets += args
    elif head == "sed" and any(f.startswith("-i") or f.startswith("--in-place") or re.match(r"^-[a-zA-Z]*i", f) for f in flags):
        # без -e / -f первый аргумент — сценарий sed, остальные — файлы
        targets += args if any(f in ("-e", "-f") or f.startswith("--expression") for f in flags) else args[1:]
    elif head == "perl" and any(re.match(r"^-[a-zA-Z]*i", f) for f in flags):
        targets += args if "-e" in flags or any(re.match(r"^-[a-zA-Z]*e$", f) for f in flags) else args[1:]
    return targets


def protected_append_path(target: str, cwd):
    """None — путь вне репозитория и памяти; иначе текст причины. cwd=None — каталог не вычислить."""
    if UNRESOLVED.search(target):
        return f"цель записи «{target}» через переменную или подстановку — путь не вычислить; укажите путь буквально или правьте инструментом Edit."
    p = os.path.expanduser(target)
    if not os.path.isabs(p):
        if cwd is None:
            return f"относительная цель «{target}» после cd на невычислимый каталог — укажите абсолютный путь."
        p = os.path.join(cwd, p)
    p = os.path.realpath(p)
    root = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd()))
    if p == root or p.startswith(root + os.sep):
        return f"дописывание или правка на месте в файл репозитория {os.path.relpath(p, root)} — только инструментом Edit (Р-651)."
    projects = os.path.realpath(os.path.expanduser("~/.claude/projects"))
    if p.startswith(projects + os.sep) and MEMORY_REL.match(p[len(projects) + 1:]):
        return f"дописывание или правка на месте в память Claude Code {p} — только инструментом Edit или Write (Р-761)."
    return None


def check_append_writes(cmd: str, cwd: str):
    """None — разрешено; иначе текст причины отказа."""
    for segment in command_segments(cmd):
        tok = shell_tokens(segment)
        while tok and ENV_ASSIGN.match(tok[0]):
            tok = tok[1:]
        if tok and tok[0] == "cd":
            dest = tok[1] if len(tok) > 1 else "~"
            if cwd is None or UNRESOLVED.search(dest) or dest == "-":
                cwd = None
            else:
                cwd = os.path.join(cwd, os.path.expanduser(dest))
            continue
        for t in append_targets(tok):
            err = protected_append_path(t, cwd)
            if err:
                return err
    return None


# --- С3: порядок поломок — снимок sha256 → поломка → прогон → откат → сверка → следующая (РП68 п. 3, Р-860) ---
class BreakageStateError(Exception):
    pass


def breakage_state_path() -> str:
    return os.path.join(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd()), ".git", "breakage.json")


def open_breakage():
    """Открытый снимок {file, sha256} или None; нечитаемый файл состояния — BreakageStateError."""
    p = breakage_state_path()
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf8") as f:
            st = json.load(f)
        if not isinstance(st.get("file"), str) or not isinstance(st.get("sha256"), str):
            raise ValueError
        return st
    except Exception:
        raise BreakageStateError(p)


def file_sha256(path: str) -> str:
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check_breakage_order(tool: str, ti: dict):
    """None — разрешено; иначе текст причины отказа."""
    try:
        st = open_breakage()
    except BreakageStateError as e:
        return f"файл снимка поломки {e} не читается — проверьте его вручную (владелец); до этого правки и коммит закрыты."
    if st is None:
        return None
    tail = f"открыт снимок поломки {st['file']}: сначала откат и python3 .claude/hooks/guard.py verify {st['file']}."
    if tool in ("Write", "Edit", "MultiEdit"):
        if os.path.realpath(ti.get("file_path", "")) != st["file"]:
            return f"правка другого файла — {tail}"
    elif tool == "Bash":
        if any(re.search(r"\bgit\b.*\bcommit\b", s) for s in command_segments(ti.get("command", ""))):
            return f"коммит с непроверенным откатом — {tail}"
    return None


def breakage_cli(cmd: str, target: str) -> int:
    path = os.path.realpath(target)
    try:
        st = open_breakage()
    except BreakageStateError as e:
        print(f"файл снимка поломки {e} не читается — проверьте его вручную.", file=sys.stderr)
        return 2
    if cmd == "snap":
        if st is not None:
            print(f"снимок уже открыт: {st['file']} — сначала откат и verify.", file=sys.stderr)
            return 1
        if not os.path.isfile(path):
            print(f"нет файла {path}.", file=sys.stderr)
            return 1
        sha = file_sha256(path)
        with open(breakage_state_path(), "w", encoding="utf8") as f:
            json.dump({"file": path, "sha256": sha}, f, ensure_ascii=False)
        print(f"снимок: {path} {sha}")
        return 0
    if st is None:
        print("открытого снимка нет.", file=sys.stderr)
        return 1
    if path != st["file"]:
        print(f"открыт снимок другого файла: {st['file']}.", file=sys.stderr)
        return 1
    sha = file_sha256(path)
    if sha != st["sha256"]:
        print(f"откат не точный: снимок {st['sha256']}, сейчас {sha}; снимок остаётся открытым.", file=sys.stderr)
        return 1
    os.remove(breakage_state_path())
    print(f"откат точный: {path} {sha}; снимок закрыт.")
    return 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] in ("snap", "verify"):
        sys.exit(breakage_cli(sys.argv[1], sys.argv[2]))
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    tool = data.get("tool_name", "")
    ti = data.get("tool_input", {}) or {}
    err = check_breakage_order(tool, ti)
    if err:
        block(err)

    if tool in ("Write", "Edit", "MultiEdit"):
        path = ti.get("file_path", "")
        if is_protected_write(path):
            block(f"запись в защищённый путь {rel(path)}. docs/reference — только чтение; .env и ключи — вне репозитория; хуки меняет владелец; снимок поломки закрывает только verify.")
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
        err = check_full_test_run(cmd)
        if err:
            block(err)
        err = check_append_writes(cmd, data.get("cwd") or os.getcwd())
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
