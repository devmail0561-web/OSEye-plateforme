"""Shared ANSI UI helpers for the oseye-server CLI."""

from __future__ import annotations

import getpass
import sys

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"
WHITE  = "\033[97m"


def c(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET


def header(title: str) -> None:
    w = 64
    print()
    print(c("┌" + "─" * (w - 2) + "┐", CYAN, BOLD))
    print(c(f"│  {title:<{w - 4}}│", CYAN, BOLD))
    print(c("└" + "─" * (w - 2) + "┘", CYAN, BOLD))


def step(n: int, total: int, title: str) -> None:
    print()
    print(c(f"  [{n}/{total}] {title}", BOLD, WHITE))
    print(c("  " + "─" * 56, DIM))


def ok(msg: str) -> None:
    print(c(f"  ✓ {msg}", GREEN))


def warn(msg: str) -> None:
    print(c(f"  ! {msg}", YELLOW))


def err(msg: str) -> None:
    print(c(f"  ✗ {msg}", RED), file=sys.stderr)


def ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        val = input(c(f"  → {prompt}{hint}: ", CYAN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    val = val.replace("\n", "").replace("\r", "")
    return val or default


def ask_password(prompt: str) -> str:
    while True:
        try:
            pw = getpass.getpass(c(f"  → {prompt}: ", CYAN))
            if len(pw) < 12:
                warn("Password must be at least 12 characters.")
                continue
            confirm = getpass.getpass(c("  → Confirm: ", CYAN))
            if pw != confirm:
                warn("Passwords do not match.")
                continue
            return pw
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)


def ask_yn(prompt: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        val = input(c(f"  → {prompt} {hint}: ", CYAN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return (val in ("y", "yes")) if val else default


