#!/usr/bin/env python3
"""Сканер репозитория и журналов прогона на ключи API, приватные ключи и номера карт.
Запуск: python3 .claude/hooks/scan_secrets.py <каталог>. Код выхода 1 при находке.
Используется в CI и для критерия приёмки №3 (журнал прогона без реквизитов)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from guard import API_KEY, PEM, has_card

SKIP_DIRS = {"node_modules", ".git", "dist", "coverage", "reference"}
EXT = {".ts", ".js", ".json", ".md", ".yaml", ".yml", ".log", ".jsonl", ".txt", ".env", ".html"}

def main(root):
    bad = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            if os.path.splitext(fn)[1] not in EXT or fn == ".env":
                continue
            p = os.path.join(dp, fn)
            try:
                txt = open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for name, hit in (("ключ API", API_KEY.search(txt)), ("приватный ключ", PEM.search(txt)), ("номер карты", has_card(txt))):
                if hit:
                    bad.append(f"{p}: {name}")
    for b in bad:
        print(b)
    print(f"Проверено. Находок: {len(bad)}")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
