"""Small ANSI terminal components used by the Ken-net menu."""

from __future__ import annotations

import shutil
import base64
import textwrap

CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


def heading(title: str, color: str = CYAN) -> None:
    width = max(56, min(shutil.get_terminal_size((80, 24)).columns, 100))
    print(f"\n{color}╭{'─' * (width - 2)}╮")
    print(f"│ {title[:width - 4].center(width - 4)} │")
    print(f"╰{'─' * (width - 2)}╯{RESET}")


def option_cards(title: str, options: list[tuple[str, str]], *, columns: int = 2, color: str = BLUE) -> None:
    heading(title, color)
    terminal_width = shutil.get_terminal_size((80, 24)).columns
    columns = max(1, min(columns, terminal_width // 32))
    cell_width = min(36, max(28, (terminal_width - 2) // columns))
    groups = [options[index:index + columns] for index in range(0, len(options), columns)]
    for group in groups:
        top = "   ".join("╭" + "─" * (cell_width - 2) + "╮" for _ in group)
        body = "   ".join("│ " + f"[{key}] {label}"[:cell_width - 4].ljust(cell_width - 4) + " │" for key, label in group)
        bottom = "   ".join("╰" + "─" * (cell_width - 2) + "╯" for _ in group)
        print(color + top + RESET)
        print(color + body + RESET)
        print(color + bottom + RESET)


def detail_card(title: str, fields: list[tuple[str, object]], *, note: str = "", color: str = GREEN) -> None:
    width = max(62, min(shutil.get_terminal_size((80, 24)).columns, 100))
    inner = width - 4
    print(f"\n{color}╭{'─' * (width - 2)}╮")
    print(f"│ {title[:inner].center(inner)} │")
    print(f"├{'─' * (width - 2)}┤{RESET}")
    for label, value in fields:
        wrapped = textwrap.wrap(str(value), width=max(20, inner - 23), break_long_words=True, break_on_hyphens=False) or [""]
        for index, line in enumerate(wrapped):
            prefix = f"{label:<19}: " if index == 0 else " " * 21
            print(f"{color}│ {prefix}{line[:inner - len(prefix)].ljust(inner - len(prefix))} │{RESET}")
    if note:
        print(f"{color}├{'─' * (width - 2)}┤{RESET}")
        for line in textwrap.wrap(note, width=inner):
            print(f"{YELLOW}│ {line.ljust(inner)} │{RESET}")
    print(f"{color}╰{'─' * (width - 2)}╯{RESET}")


def select_account(title: str, names: list[str]) -> str | None:
    """Show the roster before an account action; return a selected name or None."""
    if not names:
        print(f"{title}: no accounts are registered.")
        return None
    heading(f"{title} — REGISTERED ACCOUNTS")
    for index, name in enumerate(names, 1):
        print(f"{CYAN}[{index:02}] {name}{RESET}")
    print(f"{YELLOW}[0] Cancel{RESET}")
    choice = input("Select account number or enter username: ").strip()
    if choice in {"", "0"}:
        return None
    if choice in names:
        return choice
    if choice.isdigit():
        index = int(choice)
        if 1 <= index <= len(names):
            return names[index - 1]
        print("Invalid account number.")
        return None
    print("That username is not in the registered account list.")
    return None


def copy_prompt(items: list[tuple[str, str]]) -> None:
    """Offer OSC 52 clipboard copy for SSH terminal clients, with a visible fallback."""
    if not items:
        return
    import sys
    if not sys.stdin.isatty():
        return
    print("Copy a connection link to your local terminal clipboard:")
    for index, (label, _value) in enumerate(items, 1):
        print(f"{index}. {label}")
    print("0. Skip (select the printed link manually)")
    try:
        choice = input("Copy: ").strip()
    except EOFError:
        return
    if not choice.isdigit() or not 1 <= int(choice) <= len(items):
        return
    label, value = items[int(choice) - 1]
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    # OSC 52 lets compatible local terminal emulators set their clipboard over SSH.
    sys.stdout.write(f"\033]52;c;{encoded}\a")
    sys.stdout.flush()
    print(f"{label} sent to the terminal clipboard. If your terminal blocks OSC 52, select and copy the printed link manually.")
