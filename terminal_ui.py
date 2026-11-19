"""Small ANSI terminal components used by the Ken-net menu."""

from __future__ import annotations

import shutil
import base64
import textwrap
from datetime import date

CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


def heading(title: str, color: str = CYAN) -> None:
    width = max(40, min(shutil.get_terminal_size((80, 24)).columns, 100))
    print(f"\n{color}╭{'─' * (width - 2)}╮")
    visible_title = title if len(title) <= width - 4 else title[:width - 7] + "..."
    print(f"│ {visible_title.center(width - 4)} │")
    print(f"╰{'─' * (width - 2)}╯{RESET}")


def option_cards(title: str, options: list[tuple[str, str]], *, columns: int = 2, color: str = BLUE) -> None:
    heading(title, color)
    terminal_width = max(40, min(shutil.get_terminal_size((80, 24)).columns, 100))
    gap = "   "
    columns = max(1, min(columns, max(1, (terminal_width + len(gap)) // 34)))
    cell_width = max(30, (terminal_width - len(gap) * (columns - 1)) // columns)
    inner_width = cell_width - 4
    groups = [options[index:index + columns] for index in range(0, len(options), columns)]
    for group in groups:
        cards: list[list[str]] = []
        for key, label in group:
            marker = f"[{key}]"
            label_lines = textwrap.wrap(str(label), width=max(8, inner_width - len(marker) - 1),
                                        break_long_words=True, break_on_hyphens=False) or [""]
            card_lines = [f"{marker} {label_lines[0]}"]
            card_lines.extend((" " * (len(marker) + 1)) + line for line in label_lines[1:])
            cards.append(card_lines)
        height = max(map(len, cards), default=1) + 2
        for row in range(height):
            if row == 0:
                parts = ["╭" + "─" * (cell_width - 2) + "╮" for _ in group]
            elif row == height - 1:
                parts = ["╰" + "─" * (cell_width - 2) + "╯" for _ in group]
            else:
                parts = []
                for card in cards:
                    content = card[row - 1] if row - 1 < len(card) else ""
                    parts.append("│ " + content[:inner_width].ljust(inner_width) + " │")
            print(color + gap.join(parts) + RESET)


def metric_cards(items: list[tuple[str, object]], *, columns: int = 4, color: str = CYAN) -> None:
    """Render compact dashboard metrics in evenly sized terminal cards."""
    if not items:
        return
    width = max(40, min(shutil.get_terminal_size((80, 24)).columns, 100))
    gap = "  "
    columns = max(1, min(columns, len(items), max(1, (width + len(gap)) // 20)))
    cell_width = max(18, (width - len(gap) * (columns - 1)) // columns)
    for start in range(0, len(items), columns):
        group = items[start:start + columns]
        value_lines = [textwrap.wrap(str(value), width=cell_width - 4, break_long_words=True,
                                     break_on_hyphens=False) or [""] for _label, value in group]
        print(color + gap.join("╭" + "─" * (cell_width - 2) + "╮" for _ in group) + RESET)
        labels = [str(label)[:cell_width - 4] for label, _value in group]
        print(color + gap.join("│ " + label.center(cell_width - 4) + " │" for label in labels) + RESET)
        for row in range(max(map(len, value_lines), default=1)):
            values = [lines[row] if row < len(lines) else "" for lines in value_lines]
            print(GREEN + gap.join("│ " + value.center(cell_width - 4) + " │" for value in values) + RESET)
        print(color + gap.join("╰" + "─" * (cell_width - 2) + "╯" for _ in group) + RESET)


def detail_card(title: str, fields: list[tuple[str, object]], *, note: str = "", color: str = GREEN) -> None:
    width = max(62, min(shutil.get_terminal_size((80, 24)).columns, 100))
    inner = width - 4
    print(f"\n{color}╭{'─' * (width - 2)}╮")
    print(f"│ {title[:inner].center(inner)} │")
    print(f"├{'─' * (width - 2)}┤{RESET}")
    # Connection URIs are printed after the card as plain, isolated lines. Keeping
    # them out of a fixed-width box avoids inserting indentation or border text
    # into manual terminal selections, especially in narrow SSH clients.
    links = [(label, str(value)) for label, value in fields if label.lower().startswith("link ")]
    fields = [(label, value) for label, value in fields if not label.lower().startswith("link ")]
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
    for label, value in links:
        print(f"\n{CYAN}{label}:{RESET}")
        # Deliberately do not wrap or truncate: terminals may visually wrap the
        # line, but the output itself stays a single exact, copyable URI.
        print(f"{GREEN}{value}{RESET}")


def select_account(title: str, names: list[str], *, expired: dict[str, str] | None = None) -> str | None:
    """Show the roster before an account action; return a selected name or None."""
    if not names:
        print(f"{title}: no accounts are registered.")
        return None
    names = sorted(set(names), key=str.casefold)
    expired = expired or {}
    account_roster(title + " — SELECT ACCOUNT", [
        {"name": name, "connection": "OFFLINE" if name in expired else "—",
         "status": "EXPIRED" if name in expired else "SELECT",
         "expires": expired.get(name, "—")}
        for name in names
    ])
    print(f"{YELLOW}[0] Cancel{RESET}")
    choice = input("Select account number: ").strip()
    if choice in {"", "0"}:
        return None
    if choice.isdigit():
        index = int(choice)
        if 1 <= index <= len(names):
            return names[index - 1]
        print("Invalid account number.")
        return None
    print("That username is not in the registered account list.")
    return None


def expiry_status(expires: object) -> str:
    """Return a date-based status without claiming that a session is online."""
    if not expires:
        return "NO EXPIRY"
    try:
        value = str(expires)
        try:
            return "EXPIRED" if date.fromisoformat(value) < date.today() else "ACTIVE"
        except ValueError:
            import datetime as dt
            parsed = dt.datetime.fromisoformat(value)
            return "EXPIRED" if parsed <= dt.datetime.now(parsed.tzinfo) else "ACTIVE"
    except ValueError:
        return "UNKNOWN"


def account_roster(title: str, rows: list[dict[str, object]], *, note: str = "") -> None:
    """Render compact, numbered account rows with clear connection and expiry state."""
    heading(title, CYAN)
    if not rows:
        print(f"{YELLOW}No accounts are registered.{RESET}")
        return
    width = max(64, min(shutil.get_terminal_size((100, 24)).columns, 120))
    name_width = max(16, min(28, width - 63))
    print(f"{BLUE}{'#':>3}  {'ACCOUNT':<{name_width}}  {'CONNECTION':<12}  {'STATUS':<10}  {'VALID UNTIL':<10}{RESET}")
    print(f"{BLUE}{'─' * min(width - 4, name_width + 48)}{RESET}")
    for index, row in enumerate(rows, 1):
        name = str(row.get("name", "?"))
        connection = str(row.get("connection", "UNKNOWN")).upper()
        status = str(row.get("status", expiry_status(row.get("expires")))).upper()
        expires = str(row.get("expires", "—"))
        if len(name) > name_width:
            name = name[:name_width - 1] + "…"
        if len(expires) > 10:
            expires = expires[:10]
        connection_color = GREEN if connection in {"ONLINE", "CONNECTED", "RUNNING", "RECENT"} or connection.endswith(" SESSIONS") else YELLOW if connection in {"UNKNOWN", "N/A"} else RESET
        status_color = GREEN if status == "ACTIVE" else MAGENTA if status == "EXPIRED" else YELLOW
        print(f"{CYAN}{index:>3}{RESET}  {name:<{name_width}}  {connection_color}{connection:<12}{RESET}  {status_color}{status:<10}{RESET}  {expires:<10}")
        detail = row.get("details")
        if detail:
            print(f"     {YELLOW}↳ {detail}{RESET}")
    if note:
        print(f"{YELLOW}{note}{RESET}")


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
