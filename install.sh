#!/usr/bin/env bash
# =============================================================================
#  winDesk v1.0 — installer
#  Installs every tool winDesk orchestrates on a Debian/Ubuntu/Kali host.
#  Author: Shadi Mulla
#
#  Usage:
#     chmod +x install.sh
#     ./install.sh                 # full install (apt + kerbrute + pip)
#     ./install.sh --no-apt        # skip apt packages (pip + kerbrute only)
#     ./install.sh --no-pip        # skip pip packages
#     ./install.sh --check         # only verify what is already installed
#
#  Re-runnable: skips what is already present. Needs sudo for apt + kerbrute.
# =============================================================================
set -uo pipefail

# ---------- pretty output ----------------------------------------------------
if [ -t 1 ]; then
  R=$'\e[91m'; G=$'\e[92m'; Y=$'\e[93m'; B=$'\e[96m'; BOLD=$'\e[1m'; N=$'\e[0m'
else
  R=''; G=''; Y=''; B=''; BOLD=''; N=''
fi
ok()   { echo "${G}[+]${N} $*"; }
info() { echo "${B}[*]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
err()  { echo "${R}[-]${N} $*" >&2; }
head() { echo; echo "${B}${BOLD}=== $* ===${N}"; }

DO_APT=1; DO_PIP=1; DO_KERBRUTE=1; CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --no-apt) DO_APT=0 ;;
    --no-pip) DO_PIP=0 ;;
    --no-kerbrute) DO_KERBRUTE=0 ;;
    --check) CHECK_ONLY=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^#\s\?//'; exit 0 ;;
    *) warn "unknown option: $a" ;;
  esac
done

# ---------- sudo helper ------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
if [ -n "$SUDO" ] && ! command -v sudo >/dev/null 2>&1; then
  err "sudo not found and not running as root — re-run as root."; exit 1
fi

# =============================================================================
#  CHECK-ONLY MODE
# =============================================================================
verify() {
  head "Verifying winDesk tooling"
  local bins=(nmap nxc netexec smbclient smbmap enum4linux nbtscan snmpwalk \
              dig hashcat john kerbrute certipy-ad bloodhound-python \
              impacket-GetNPUsers xfreerdp python3)
  for b in "${bins[@]}"; do
    if command -v "$b" >/dev/null 2>&1; then
      ok "$b"
    else
      warn "$b  (missing — some phases will degrade/skip)"
    fi
  done
  info "Python libraries:"
  python3 - <<'PY' 2>/dev/null || true
for m in ("impacket", "ldap3", "dns", "certipy"):
    try:
        __import__(m); print(f"  [+] python:{m}")
    except Exception:
        print(f"  [!] python:{m}  (missing)")
PY
}

if [ "$CHECK_ONLY" -eq 1 ]; then verify; exit 0; fi

cat <<BANNER
${B}${BOLD}
 __      ___      ___         _
 \\ \\    / (_)_ _ |   \\ ___ __| |__
  \\ \\/\\/ /| | ' \\| |) / -_|_-< / /
   \\_/\\_/ |_|_||_|___/\\___/__/_\\_\\  installer  v1.0
${N}
BANNER
warn "Install these tools only on a system you own or are authorized to use."

# =============================================================================
#  1) APT SYSTEM PACKAGES
# =============================================================================
if [ "$DO_APT" -eq 1 ]; then
  head "APT packages"
  info "apt update"
  $SUDO apt update -y || warn "apt update returned non-zero (continuing)"

  # Core enumeration + cracking + AD tooling. Packages that do not exist on a
  # given distro are tried individually so one miss never aborts the run.
  APT_PKGS=(
    nmap netexec crackmapexec smbclient smbmap enum4linux nbtscan
    snmp snmp-mibs-downloader dnsutils
    hashcat john
    krb5-user samba-common-bin ldap-utils
    python3-impacket impacket-scripts
    python3-ldap3 python3-dnspython
    freerdp2-x11 xfreerdp2-x11
    bloodhound.py
    seclists wordlists
    git curl wget gzip python3-pip python3-venv pipx
  )
  info "Installing (missing packages are skipped automatically)…"
  for pkg in "${APT_PKGS[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      ok "$pkg (already installed)"
    elif $SUDO apt install -y "$pkg" >/dev/null 2>&1; then
      ok "$pkg"
    else
      warn "$pkg not available via apt on this distro — skipped"
    fi
  done
else
  warn "skipping apt packages (--no-apt)"
fi

# =============================================================================
#  2) KERBRUTE  (static binary — not in apt)
# =============================================================================
if [ "$DO_KERBRUTE" -eq 1 ]; then
  head "kerbrute"
  if command -v kerbrute >/dev/null 2>&1; then
    ok "kerbrute already installed ($(command -v kerbrute))"
  else
    info "Downloading kerbrute v1.0.3 (linux/amd64) → /usr/local/bin/kerbrute"
    if $SUDO wget -q https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 \
         -O /usr/local/bin/kerbrute; then
      $SUDO chmod +x /usr/local/bin/kerbrute
      ok "kerbrute installed → $(kerbrute 2>/dev/null | head -n1 || echo /usr/local/bin/kerbrute)"
    else
      warn "kerbrute download failed — install it manually from https://github.com/ropnop/kerbrute"
    fi
  fi
else
  warn "skipping kerbrute (--no-kerbrute)"
fi

# =============================================================================
#  3) PYTHON PACKAGES  (pip — handles PEP-668 externally-managed Kali hosts)
# =============================================================================
if [ "$DO_PIP" -eq 1 ]; then
  head "Python packages (pip)"
  PIP_PKGS=(impacket ldap3 dnspython certipy-ad bloodhound)

  # Choose an install strategy that works on modern Kali (PEP 668):
  #   1. active virtualenv   → plain pip
  #   2. pipx present        → pipx for the CLI tools, pip --break for libs
  #   3. fallback            → pip install --break-system-packages
  PIP="python3 -m pip install --upgrade"
  BREAK=""
  if [ -z "${VIRTUAL_ENV:-}" ]; then
    if python3 -m pip install --help 2>/dev/null | grep -q -- "--break-system-packages"; then
      BREAK="--break-system-packages"
    fi
  fi

  info "pip install ${PIP_PKGS[*]} ${BREAK}"
  if $PIP "${PIP_PKGS[@]}" $BREAK 2>/dev/null; then
    ok "python packages installed/upgraded"
  else
    warn "bulk pip install hit an error — retrying one by one"
    for p in "${PIP_PKGS[@]}"; do
      if $PIP "$p" $BREAK >/dev/null 2>&1; then ok "pip:$p"; else warn "pip:$p failed (install manually)"; fi
    done
  fi

  # Optional but handy AD utility the methodology references.
  info "pip install bloodyAD (optional AD read/write utility)"
  $PIP bloodyAD $BREAK >/dev/null 2>&1 && ok "pip:bloodyAD" || warn "pip:bloodyAD skipped"
else
  warn "skipping pip packages (--no-pip)"
fi

# =============================================================================
#  4) WORDLIST CONVENIENCE  (unpack rockyou if present but gzipped)
# =============================================================================
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  head "rockyou"
  info "Decompressing rockyou.txt"
  $SUDO gzip -dk /usr/share/wordlists/rockyou.txt.gz 2>/dev/null && ok "rockyou.txt ready" || warn "could not decompress rockyou"
fi

# =============================================================================
#  DONE
# =============================================================================
verify
head "Done"
ok "winDesk dependencies installed. Verify the tool itself with:"
echo "    python3 winDesk.py --self-test"
echo "    python3 winDesk.py <target> --userlist users.txt --passlist pass.txt"
