#!/usr/bin/env python3
"""Audit and narrow an OpenRGB SDK server that runs under a dedicated account.

  check        read-only report on the service, device permissions and autostart
  devices      list the controllers the SDK server reports
  udev-rules   print udev rules granting the account only the HID interfaces
               the running server has open

Run `check` and `udev-rules` with sudo; `devices` needs no privileges.
"""

import argparse
import collections
import glob
import grp
import os
import pwd
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

SERVICE = "openrgb.service"
ACCOUNT = "openrgb"
SDK_HOST = "127.0.0.1"
SDK_PORT = 6742
PACKAGED_RULES = "/usr/lib/udev/rules.d/60-openrgb.rules"

# Top-level HID application collections that deliver user input.
INPUT_USAGES = {
    (0x01, 0x02): "mouse",
    (0x01, 0x04): "joystick",
    (0x01, 0x05): "gamepad",
    (0x01, 0x06): "keyboard",
    (0x01, 0x07): "keypad",
    (0x01, 0x80): "system control",
    (0x0C, 0x01): "consumer control",
    (0x0D, 0x02): "pen",
    (0x0D, 0x04): "touch screen",
    (0x0D, 0x05): "touch pad",
}

warnings = 0


def report(level, message):
    global warnings
    if level == "WARN":
        warnings += 1
    print(f"{level:<4} {message}")


def heading(title):
    print(f"\n== {title}")


def run(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True).stdout
    except FileNotFoundError:
        return ""


def read(path, default=None):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return default


def user_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def group_name(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


# --- SDK protocol -----------------------------------------------------------

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("server closed the connection")
        data += chunk
    return data


def sdk_send(sock, packet_id, device=0, data=b""):
    sock.sendall(b"ORGB" + struct.pack("<III", device, packet_id, len(data)) + data)


def sdk_request(sock, packet_id, device=0):
    sdk_send(sock, packet_id, device)
    while True:
        magic, _, reply_id, size = struct.unpack("<4sIII", recv_exact(sock, 16))
        if magic != b"ORGB":
            raise ConnectionError("not an OpenRGB SDK server")
        body = recv_exact(sock, size)
        # Skip unsolicited packets such as device-list updates.
        if reply_id == packet_id:
            return body


def sdk_devices(host=SDK_HOST, port=SDK_PORT):
    """Names of the controllers the server reports. Reads only; sets no colors."""
    with socket.create_connection((host, port), timeout=5) as sock:
        sdk_send(sock, 50, data=b"openrgb-hardening check\0")
        (count,) = struct.unpack_from("<I", sdk_request(sock, 0))
        names = []
        for index in range(count):
            # Protocol 0 layout: data size, device type, name length, name.
            body = sdk_request(sock, 1, index)
            (length,) = struct.unpack_from("<H", body, 8)
            names.append(body[10:10 + length].rstrip(b"\0").decode(errors="replace"))
        return names


# --- Device introspection ---------------------------------------------------

def hid_usages(descriptor):
    """(usage page, usage) of each top-level collection in a HID report descriptor."""
    usages = []
    page, usage, depth, i = 0, None, 0, 0
    while i < len(descriptor):
        prefix = descriptor[i]
        if prefix == 0xFE:  # long item
            i += 3 + (descriptor[i + 1] if i + 1 < len(descriptor) else 0)
            continue
        size = (0, 1, 2, 4)[prefix & 3]
        value = int.from_bytes(descriptor[i + 1:i + 1 + size], "little")
        kind, tag = (prefix >> 2) & 3, prefix >> 4
        if kind == 1 and tag == 0:
            page = value
        elif kind == 2 and tag == 0 and usage is None:
            usage = (value >> 16, value & 0xFFFF) if size == 4 else (page, value)
        elif kind == 0 and tag == 0xA:
            if depth == 0:
                usages.append(usage or (page, 0))
            depth += 1
        elif kind == 0 and tag == 0xC:
            depth = max(0, depth - 1)
        if kind == 0:
            usage = None
        i += 1 + size
    return usages


def hidraw_info(node):
    """USB identity and top-level usages of a /dev/hidrawN node."""
    hid = Path("/sys/class/hidraw", Path(node).name, "device").resolve()
    info = {"node": str(node), "usb": False, "interface": None}
    for parent in hid.parents:
        if info["interface"] is None and (parent / "bInterfaceNumber").exists():
            info["interface"] = read(parent / "bInterfaceNumber")
        if (parent / "idVendor").exists():
            info.update(
                usb=True,
                vendor=read(parent / "idVendor"),
                product=read(parent / "idProduct"),
                name=" ".join(filter(None, (read(parent / "manufacturer"), read(parent / "product")))),
            )
            break
    try:
        info["usages"] = hid_usages((hid / "report_descriptor").read_bytes())
    except OSError:
        info["usages"] = []
    info["input"] = [INPUT_USAGES[u] for u in info["usages"] if u in INPUT_USAGES]
    return info


def describe_identity(info):
    if not info["usb"]:
        return "non-USB"
    return f"{info['vendor']}:{info['product']} if{info['interface']}"


def describe_usages(info):
    return ", ".join(INPUT_USAGES.get(u, f"{u[0]:04x}:{u[1]:04x}") for u in info["usages"]) or "?"


def acl_entries(path):
    """Named user and group entries of a POSIX access ACL as (kind, id, perms)."""
    try:
        raw = os.getxattr(path, "system.posix_acl_access")
    except OSError:
        return []
    entries = []
    for offset in range(4, len(raw) - 7, 8):
        tag, perm, ident = struct.unpack_from("<HHI", raw, offset)
        if tag in (2, 8):
            entries.append(("user" if tag == 2 else "group", ident, perm))
    return entries


def describe_acl(entries):
    return " ".join(
        f"{kind}:{user_name(ident) if kind == 'user' else group_name(ident)}:"
        + "".join(c if perm & bit else "-" for c, bit in (("r", 4), ("w", 2), ("x", 1)))
        for kind, ident, perm in entries
    )


def can_open(path, st, uid, gids, need=6):
    """Approximate DAC check for read (4) and/or write (2) access; ignores the ACL mask."""
    if uid == 0:
        return True
    if st.st_uid == uid:
        return bool(st.st_mode & need << 6)
    for kind, ident, perm in acl_entries(path):
        if (kind == "user" and ident == uid) or (kind == "group" and ident in gids):
            if perm & need:
                return True
    if st.st_gid in gids:
        return bool(st.st_mode & need << 3)
    return bool(st.st_mode & need)


def rule_files(pattern):
    """udev rules files with a line matching pattern, to find where a grant comes from."""
    files = []
    for directory in ("/etc/udev/rules.d", "/run/udev/rules.d", "/usr/lib/udev/rules.d"):
        for path in sorted(glob.glob(f"{directory}/*.rules")):
            if re.search(pattern, read(path, ""), re.I | re.M):
                files.append(path)
    return " ".join(files) or "no matching rules file"


def describe_node(path, st):
    return f"{user_name(st.st_uid)}:{group_name(st.st_gid)} {stat.S_IMODE(st.st_mode):04o}"


def udev_properties(st):
    kind = "c" if stat.S_ISCHR(st.st_mode) else "b"
    data = read(f"/run/udev/data/{kind}{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}", "")
    return dict(line[2:].split("=", 1) for line in data.splitlines() if line.startswith("E:") and "=" in line)


def identity(name):
    """uid and group ids of an account, or None if it doesn't exist."""
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        return None
    return pw.pw_uid, set(os.getgrouplist(name, pw.pw_gid))


def server_pid():
    pid = run("systemctl", "show", "-p", "MainPID", "--value", SERVICE).strip()
    return int(pid) if pid.isdigit() and pid != "0" else None


def open_files(pid):
    targets = []
    for fd in glob.glob(f"/proc/{pid}/fd/*"):
        try:
            targets.append(os.readlink(fd))
        except OSError:
            pass
    return targets


# --- check ------------------------------------------------------------------

def check_service():
    heading("Service")
    print(run("systemctl", "cat", SERVICE).rstrip())
    properties = run(
        "systemctl", "show", SERVICE, "-p", "ActiveState", "-p", "User", "-p", "Group",
        "-p", "SupplementaryGroups", "-p", "DevicePolicy", "-p", "DeviceAllow",
        "-p", "RestrictAddressFamilies", "-p", "IPAddressAllow", "-p", "IPAddressDeny",
        "-p", "RestrictNetworkInterfaces", "-p", "SocketBindAllow", "-p", "SocketBindDeny",
        "-p", "PrivateDevices", "-p", "ProtectSystem", "-p", "ProtectHome",
        "-p", "ProtectProc", "-p", "ProcSubset", "-p", "MemoryDenyWriteExecute",
        "-p", "SystemCallArchitectures", "-p", "ControlGroup",
    )
    print()
    print(properties.rstrip())
    values = dict(line.split("=", 1) for line in properties.splitlines() if "=" in line)
    report("ok" if values.get("ActiveState") == "active" else "WARN", f"{SERVICE} is {values.get('ActiveState')}")
    if values.get("SupplementaryGroups"):
        report("WARN", f"SupplementaryGroups={values['SupplementaryGroups']}")

    pid = server_pid()
    if pid is None:
        return None
    status = dict(
        line.split(":", 1) for line in read(f"/proc/{pid}/status", "").splitlines() if ":" in line
    )
    fields = {k: status.get(k, "").strip() for k in ("Uid", "Gid", "Groups", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp")}
    print()
    for key, value in fields.items():
        print(f"{key}: {value}")
    print(f"SELinux: {read(f'/proc/{pid}/attr/current', '-').rstrip(chr(0))}")
    account = identity(ACCOUNT)
    if account and fields["Uid"].split()[:1] != [str(account[0])]:
        report("WARN", f"server is not running as {ACCOUNT}")
    if int(fields["CapEff"] or "0", 16) or int(fields["CapAmb"] or "0", 16):
        report("WARN", "server has effective or ambient capabilities")
    if fields["NoNewPrivs"] != "1":
        report("WARN", "NoNewPrivs is not set")
    if fields["Seccomp"] != "2":
        report("WARN", "no seccomp filter")
    if account:
        extra = {int(g) for g in fields["Groups"].split()} - {pwd.getpwnam(ACCOUNT).pw_gid}
        if extra:
            report("WARN", "server has supplementary groups: " + " ".join(group_name(g) for g in sorted(extra)))
    return pid


def check_network(pid):
    heading("Network")
    server_inodes = {
        t[len("socket:["):-1] for t in open_files(pid) if t.startswith("socket:[")
    } if pid else set()
    for table, family in (("/proc/net/tcp", socket.AF_INET), ("/proc/net/tcp6", socket.AF_INET6)):
        for line in read(table, "").splitlines()[1:]:
            fields = line.split()
            address, port = fields[1].split(":")
            if fields[3] != "0A":  # LISTEN
                continue
            raw = bytes.fromhex(address)
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            host = socket.inet_ntop(family, raw)
            port = int(port, 16)
            owned = fields[9] in server_inodes
            if owned or port == SDK_PORT:
                loopback = host in ("127.0.0.1", "::1")
                report("ok" if owned and loopback and port == SDK_PORT else "WARN",
                       f"{host}:{port} listening ({'server' if owned else 'another process'})")


def check_sdk(expect):
    heading("SDK controllers")
    try:
        names = sdk_devices()
    except OSError as error:
        report("WARN", f"cannot query {SDK_HOST}:{SDK_PORT}: {error}")
        return
    for name in names:
        print(f"     {name}")
    if expect is not None and len(names) < expect:
        report("WARN", f"{len(names)} controllers, expected {expect}")
    else:
        report("ok", f"{len(names)} controllers")


def check_hidraw(pid, account, desktop):
    heading("HID interfaces")
    in_use = {t for t in open_files(pid) if t.startswith("/dev/hidraw")} if pid else set()
    for node in sorted(glob.glob("/dev/hidraw*"), key=lambda n: int(re.sub(r"\D", "", n) or 0)):
        st = os.stat(node)
        info = hidraw_info(node)
        acl = acl_entries(node)
        used = node in in_use
        print(
            f"     {node:<14} {describe_identity(info):<20} {describe_node(node, st)}\n"
            f"     {'':<14} {info.get('name', '')} [{describe_usages(info)}]"
            + (f" acl: {describe_acl(acl)}" if acl else "")
            + (" <- server" if used else "")
        )
        if used and info["input"]:
            report("WARN", f"{node} is used by the server and also carries {', '.join(info['input'])} reports")
        if account and not used and can_open(node, st, *account):
            report("WARN", f"{ACCOUNT} can open {node} ({describe_identity(info)}), which the server doesn't use")
        if desktop and info["input"] and can_open(node, st, *desktop):
            report("WARN", f"{desktop_name} can open {node}, which carries {', '.join(info['input'])} reports")
            if info["usb"]:
                print(f"     rules mentioning {info['vendor']}: {rule_files(info['vendor'])}")
        if st.st_mode & 0o006:
            report("WARN", f"{node} is accessible to everyone")
    for node in sorted(in_use):
        report("ok", f"server uses {node} ({describe_identity(hidraw_info(node))})")


def check_other_devices(account, desktop):
    heading("Input, I2C and raw USB devices")
    found = False
    for node in sorted(glob.glob("/dev/input/event*")):
        st = os.stat(node)
        props = udev_properties(st)
        if props.get("ID_INPUT_KEYBOARD") != "1":
            continue
        found = True
        acl = acl_entries(node)
        print(f"     {node:<20} {describe_node(node, st):<20} {props.get('ID_SERIAL', '')}"
              + (f" acl: {describe_acl(acl)}" if acl else ""))
        for name, ids in ((ACCOUNT, account), (desktop_name, desktop)):
            if ids and can_open(node, st, *ids):
                report("WARN", f"{name} can open keyboard event node {node}")
    if not found:
        report("WARN", "no keyboard event nodes found in the udev database")
    else:
        report("ok", "keyboard event nodes checked")
    # usbfs nodes are world-readable by default (descriptors only); only write access matters.
    for pattern, need, rules in (("/dev/i2c-*", 6, r"i2c"), ("/dev/bus/usb/*/*", 2, r"SUBSYSTEMS?==\"usb"), ("/dev/uinput", 6, r"uinput")):
        accounts = ((ACCOUNT, account),) if pattern.startswith("/dev/bus") else ((ACCOUNT, account), (desktop_name, desktop))
        flagged = False
        for node in sorted(glob.glob(pattern)):
            st = os.stat(node)
            acl = acl_entries(node)
            for name, ids in accounts:
                if ids and can_open(node, st, *ids, need=need):
                    flagged = True
                    report("WARN", f"{name} can {'write' if need == 2 else 'open'} {node} ({describe_node(node, st)}"
                           + (f" acl: {describe_acl(acl)})" if acl else ")"))
        if flagged and not pattern.startswith("/dev/bus"):
            print(f"     rules mentioning {rules}: {rule_files(rules)}")
    i2c_loads = [f for f in glob.glob("/etc/modules-load.d/*.conf") if re.search(r"^\s*i2c[-_]dev", read(f, ""), re.M)]
    for path in i2c_loads:
        report("info", f"{path} loads i2c-dev at boot")


def check_udev_rules():
    heading("udev rules")
    for path in sorted(glob.glob("/usr/lib/udev/rules.d/*openrgb*") + glob.glob("/etc/udev/rules.d/*.rules")):
        text = read(path, "")
        if path.startswith("/etc/") and ACCOUNT not in text.lower() and "openrgb" not in path:
            continue
        rules = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        print(f"     {path}: {len(rules)} rules")
        if path.startswith("/etc/"):
            for line in rules:
                if re.search(r"uaccess|i2c|SUBSYSTEM==\"input\"|KERNEL==\"(event|uinput)", line):
                    report("WARN", f"{path}: {line.strip()}")
                elif "hidraw" not in line and ("GROUP=" in line or "MODE=" in line):
                    report("info", f"{path}: {line.strip()}")
    for path in sorted(glob.glob("/etc/systemd/system/openrgb.service.d/*")):
        print(f"     drop-in {path}")


def check_desktop_user():
    heading(f"Desktop user {desktop_name or '(unknown)'}")
    if not desktop_name:
        report("WARN", "run with sudo from the desktop account, or pass --user")
        return None
    ids = identity(desktop_name)
    groups = {group_name(g) for g in ids[1]}
    for group in ("input", ACCOUNT, "i2c"):
        report("WARN" if group in groups else "ok", f"{desktop_name} {'is' if group in groups else 'is not'} in {group}")

    home = Path(pwd.getpwnam(desktop_name).pw_dir)
    autostart = glob.glob(str(home / ".config/autostart/*.desktop")) + glob.glob("/etc/xdg/autostart/*.desktop")
    for path in autostart:
        text = read(path, "")
        if re.search(r"^Exec=.*openrgb", text, re.M | re.I):
            hidden = re.search(r"^(Hidden=true|X-GNOME-Autostart-enabled=false)", text, re.M)
            report("ok" if hidden else "WARN", f"autostart {path} {'is disabled' if hidden else 'starts OpenRGB'}")
    for base in (home / ".config/systemd/user", Path("/etc/systemd/user")):
        for path in base.rglob("*"):
            if "openrgb" in path.name.lower():
                report("WARN", f"user unit {path}")
    for comm in glob.glob("/proc/[0-9]*/comm"):
        if read(comm) != "openrgb":
            continue
        proc = Path(comm).parent
        try:
            uid = proc.stat().st_uid
        except OSError:
            continue
        if user_name(uid) != ACCOUNT:
            cmdline = read(proc / "cmdline", "").replace("\0", " ")
            report("WARN", f"openrgb running as {user_name(uid)} (pid {proc.name}): {cmdline}")
    return ids


def check_logs():
    heading("Journal (this boot)")
    pattern = re.compile(r"bpf|not supported|unsupported|denied|not permitted|failed|error", re.I)
    # Logged whenever an SDK client disconnects.
    routine = re.compile(r"recv_select failed receiving magic")
    lines = [
        l for l in run("journalctl", "-u", SERVICE, "-b", "-o", "short-monotonic", "--no-pager").splitlines()
        if pattern.search(l) and not routine.search(l)
    ]
    print("\n".join(lines[-30:]) or "     (nothing matching)")
    heading("SELinux denials (this boot)")
    if shutil.which("ausearch"):
        avcs = [l for l in run("ausearch", "-m", "AVC,USER_AVC", "-ts", "boot", "-i").splitlines() if "openrgb" in l]
        print("\n".join(avcs[-40:]) or "     no AVCs mentioning openrgb this boot")


def command_check(args):
    global desktop_name
    if os.geteuid() != 0:
        sys.exit("check needs root: sudo ./openrgb-hardening.py check")
    desktop_name = args.user or os.environ.get("SUDO_USER")
    account = identity(ACCOUNT)
    if account is None:
        report("WARN", f"no {ACCOUNT} account")
    desktop = check_desktop_user()
    pid = check_service()
    check_network(pid)
    check_sdk(args.expect)
    check_hidraw(pid, account, desktop)
    check_other_devices(account, desktop)
    check_udev_rules()
    check_logs()
    print(f"\n{warnings} warning(s)")
    return 1 if warnings else 0


# --- devices ----------------------------------------------------------------

def command_devices(args):
    if not args.expect_file:
        for name in sdk_devices():
            print(name)
        return 0
    expected = collections.Counter(Path(args.expect_file).read_text().splitlines())
    deadline = time.monotonic() + args.timeout
    missing = expected
    while time.monotonic() < deadline:
        try:
            missing = expected - collections.Counter(sdk_devices())
        except OSError:
            pass
        else:
            if not missing:
                print("all controllers present")
                return 0
        time.sleep(3)
    print("missing after %ds: %s" % (args.timeout, ", ".join(missing.elements())), file=sys.stderr)
    return 1


# --- udev-rules -------------------------------------------------------------

def parse_ids(values):
    """VID:PID or VID:PID:IF arguments as tuples of lowercase strings."""
    ids = []
    for value in values or ():
        parts = tuple(value.lower().split(":"))
        if len(parts) not in (2, 3):
            sys.exit(f"expected VID:PID or VID:PID:IF, got {value}")
        ids.append(parts)
    return ids


def packaged_ids():
    """(vendor, product) pairs of the devices OpenRGB's packaged rules cover."""
    text = read(PACKAGED_RULES, "")
    pairs = re.findall(r'ATTRS\{idVendor\}=="([0-9a-fA-F]{4})".*?ATTRS\{idProduct\}=="([0-9a-fA-F]{4})"', text)
    return {(v.lower(), p.lower()) for v, p in pairs}


def command_udev_rules(args):
    if args.bootstrap:
        supported = packaged_ids()
        if not supported:
            sys.exit(f"no device IDs found in {PACKAGED_RULES}")
        interfaces = []
        for node in glob.glob("/dev/hidraw*"):
            info = hidraw_info(node)
            # Input interfaces are never needed for lighting; leave them out quietly.
            if info["usb"] and (info["vendor"], info["product"]) in supported and not info["input"]:
                interfaces.append(info)
    elif args.interface:
        wanted = parse_ids(args.interface)
        interfaces = []
        for node in glob.glob("/dev/hidraw*"):
            info = hidraw_info(node)
            if info["usb"] and (info["vendor"], info["product"], info["interface"]) in wanted:
                interfaces.append(info)
    else:
        if os.geteuid() != 0:
            sys.exit("reading the server's open devices needs root")
        pid = server_pid()
        if pid is None:
            sys.exit(f"{SERVICE} is not running")
        interfaces = [hidraw_info(t) for t in sorted(set(open_files(pid))) if t.startswith("/dev/hidraw")]
    excluded = parse_ids(args.exclude)
    interfaces = [
        info for info in interfaces
        if not (info["usb"] and any(
            (info["vendor"], info["product"], info["interface"])[:len(e)] == e for e in excluded
        ))
    ]
    if not interfaces:
        sys.exit("no HID interfaces found")

    unique = {}
    for info in interfaces:
        if not info["usb"]:
            sys.exit(f"{info['node']} is not a USB device; write its rule by hand")
        if info["input"] and not args.allow_input:
            sys.exit(
                f"{info['node']} ({describe_identity(info)}) carries {', '.join(info['input'])} reports; "
                "granting it lets the service read that input. Pass --allow-input to accept."
            )
        unique[(info["vendor"], info["product"], info["interface"])] = info

    print(f"""\
# Shadows the packaged rules of the same name. Grants the {ACCOUNT} group the HID
# interfaces below and nothing else; other devices keep their default permissions.
# Generated by openrgb-hardening.py udev-rules.
ACTION=="remove", GOTO="openrgb_end"
SUBSYSTEM!="hidraw", GOTO="openrgb_end"
SUBSYSTEMS=="usb", IMPORT{{builtin}}="usb_id"
ENV{{ID_BUS}}!="usb", GOTO="openrgb_end"
""")
    for (vendor, product, interface), info in sorted(unique.items()):
        print(f"# {info['name'] or 'unnamed'}, interface {interface} [{describe_usages(info)}]")
        print(
            f'ENV{{ID_VENDOR_ID}}=="{vendor}", ENV{{ID_MODEL_ID}}=="{product}", '
            f'ENV{{ID_USB_INTERFACE_NUM}}=="{interface}", GROUP="{ACCOUNT}", MODE="0660"'
        )
    print('\nLABEL="openrgb_end"')
    return 0


desktop_name = None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("check", help="read-only report (sudo)")
    p.add_argument("--user", help="desktop account to check (default: $SUDO_USER)")
    p.add_argument("--expect", type=int, help="minimum number of controllers")
    p.set_defaults(func=command_check)
    p = sub.add_parser("devices", help="list controllers reported by the SDK server")
    p.add_argument("--expect-file", help="wait until every name in this file is reported")
    p.add_argument("--timeout", type=int, default=90)
    p.set_defaults(func=command_devices)
    p = sub.add_parser("udev-rules", help="print udev rules for the interfaces in use (sudo)")
    p.add_argument("--interface", action="append", metavar="VID:PID:IF",
                   help="use this interface instead of the server's open ones (repeatable)")
    p.add_argument("--bootstrap", action="store_true",
                   help="first install: every non-input interface of connected devices OpenRGB supports")
    p.add_argument("--exclude", action="append", metavar="VID:PID[:IF]",
                   help="leave out this device or interface (repeatable)")
    p.add_argument("--allow-input", action="store_true",
                   help="accept interfaces that also carry keyboard/mouse reports")
    p.set_defaults(func=command_udev_rules)
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
