#!/usr/bin/env python3
"""Editable terminal manager for the known Ken-net server helpers.

This frontend deliberately delegates account changes to the server's existing
protocol helpers. It does not edit service configuration itself.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class Protocol:
    key: str
    title: str
    service: str | None
    add: str | None = None
    delete: str | None = None
    renew: str | None = None
    note: str = ""


PROTOCOLS = (
    Protocol("ssh", "SSH", "ssh", "/usr/bin/add-ssh", "/usr/bin/del-ssh", "/usr/bin/renew-ssh"),
    Protocol("tls", "TLS (transport setting)", "nginx", note="TLS is a transport/security setting, not a standalone account protocol."),
    Protocol("vless", "VLESS", "xray", "/usr/bin/add-vless", "/usr/bin/del-vless", "/usr/bin/renew-vless"),
    Protocol("trojan", "Trojan", "xray", "/usr/bin/add-tr", "/usr/bin/del-tr", "/usr/bin/renew-tr"),
    Protocol("vmess", "VMess", "xray", "/usr/bin/add-ws", "/usr/bin/del-ws", "/usr/bin/renew-ws"),
    Protocol("udp", "UDP tunnel", "udp", note="Active service detected; account management commands still need to be mapped."),
    Protocol("wireguard", "WireGuard", "wg-quick", note="Detected/configured WireGuard interfaces can be inspected; peer provisioning is not yet configured."),
    Protocol("slowdns", "SlowDNS", "server", note="This server runs SlowDNS through dnstt-server; no per-user account helper was identified."),
    Protocol("dnstt", "DNSTT", "server", note="The server runs dnstt-server and dnstt-client; this appears to be the SlowDNS transport instance."),
)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def systemd_active(service: str) -> bool:
    if not shutil.which("systemctl"):
        return False
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def protocol_state(protocol: Protocol) -> tuple[str, str]:
    if protocol.key == "wireguard":
        if not shutil.which("wg"):
            return "غير مهيأ", "الأداة wg غير مثبتة"
        configs = sorted(Path("/etc/wireguard").glob("*.conf")) if Path("/etc/wireguard").is_dir() else []
        if not configs:
            return "غير مهيأ", "لا توجد ملفات /etc/wireguard/*.conf"
        active = [p.stem for p in configs if systemd_active(f"wg-quick@{p.stem}.service")]
        if active:
            return "نشط", "واجهات WireGuard: " + ", ".join(active)
        return "موجود", f"WireGuard مثبت؛ ملفات إعداد: {len(configs)}"
    if protocol.key == "udp":
        if systemd_active("udp") and Path("/usr/bin/udp").is_file() and Path("/usr/bin/config.json").is_file():
            return "نشط", "udp.service يعمل، وملف الإعداد موجود؛ إدارة الحسابات لم تُحدد بعد"
        return "غير جاهز", "تحقق من udp.service و/usr/bin/udp وملف الإعداد"
    if protocol.key in {"slowdns", "dnstt"}:
        if systemd_active("kennet-dnstt-router.service"):
            return "نشط", "موجّه DNSTT متعدد النطاقات يعمل؛ كل حساب له مفتاح وخدمة مستقلة"
        server_up = systemd_active("server") and Path("/etc/slowdns/dnstt-server").is_file()
        client_up = systemd_active("client") and Path("/etc/slowdns/dnstt-client").is_file()
        if server_up and client_up:
            return "نشط", "خدمتا dnstt-server وdnstt-client تعملان؛ لا توجد أداة حسابات فردية معروفة"
        if server_up:
            return "نشط جزئياً", "خدمة dnstt-server تعمل؛ تحقق من خدمة dnstt-client"
        return "غير جاهز", protocol.note
    if protocol.key == "tls":
        if protocol.key == "tls" and systemd_active("nginx"):
            return "نشط جزئياً", "nginx نشط؛ لم يتم التحقق من شهادة TLS لكل inbound"
        return "غير جاهز", protocol.note
    if protocol.service and systemd_active(protocol.service):
        missing = [p for p in (protocol.add, protocol.delete, protocol.renew) if p and not Path(p).is_file()]
        if missing:
            return "الخدمة نشطة", "ملفات الإدارة الناقصة: " + ", ".join(missing)
        return "جاهز عبر أدوات الخادم", f"الخدمة {protocol.service} نشطة وأدوات الحساب موجودة"
    return "متوقف أو غير مثبت", f"الخدمة {protocol.service} غير نشطة"


def run_helper(path: str | None) -> int:
    if not path or not Path(path).is_file():
        print("أداة الإدارة غير موجودة على هذا الخادم.")
        return 1
    if not os.access(path, os.X_OK):
        print(f"الأداة غير قابلة للتنفيذ: {path}")
        return 1
    try:
        return subprocess.run([path], check=False).returncode
    except OSError as exc:
        print(f"تعذر تشغيل الأداة: {exc}")
        return 1


def show_status() -> None:
    print("\nحالة البروتوكولات")
    for p in PROTOCOLS:
        state, detail = protocol_state(p)
        print(f"- {p.title}: {state} — {detail}")


def choose_protocol() -> Protocol | None:
    for i, p in enumerate(PROTOCOLS, 1):
        print(f"{i}. {p.title}")
    raw = input("اختر البروتوكول (0 للعودة): ").strip()
    if raw == "0":
        return None
    try:
        index = int(raw) - 1
        return PROTOCOLS[index] if 0 <= index < len(PROTOCOLS) else None
    except ValueError:
        return None


def manage_protocol(p: Protocol) -> None:
    state, detail = protocol_state(p)
    print(f"\n{p.title}: {state} — {detail}")
    if not is_root():
        print("إدارة الحسابات تتطلب تشغيل البرنامج بصلاحية root.")
        return
    if p.key == "wireguard":
        import wireguard_manager
        wireguard_manager.menu()
        return
    if p.key in {"slowdns", "dnstt"}:
        import dnstt_manager
        dnstt_manager.menu()
        return
    actions: tuple[tuple[str, str | None], ...] = (("إنشاء حساب", p.add), ("حذف حساب", p.delete), ("تجديد حساب", p.renew))
    available = [(label, path) for label, path in actions if path]
    if not available:
        print("لا توجد أداة إنشاء/حذف/تجديد موثقة لهذا البروتوكول حتى الآن.")
        return
    for i, (label, _) in enumerate(available, 1):
        print(f"{i}. {label}")
    print("0. رجوع")
    try:
        selected = int(input("اختر العملية: ").strip())
    except ValueError:
        print("اختيار غير صالح.")
        return
    if selected == 0:
        return
    if not 1 <= selected <= len(available):
        print("اختيار غير صالح.")
        return
    label, helper = available[selected - 1]
    print(f"سيتم تمرير العملية إلى أداة الخادم: {label}.")
    run_helper(helper)


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("هذا البرنامج مخصص للتشغيل على خادم Ubuntu/Linux.")
        return 2
    while True:
        print("\n=== مدير الحسابات الخاص ===")
        print("1. حالة البروتوكولات")
        print("2. إدارة بروتوكول")
        print("0. خروج")
        choice = input("اختر: ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            show_status()
        elif choice == "2":
            p = choose_protocol()
            if p:
                manage_protocol(p)
        else:
            print("اختيار غير صالح.")


if __name__ == "__main__":
    raise SystemExit(main())

