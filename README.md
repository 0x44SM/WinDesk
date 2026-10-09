<h1 align="center">WinDesk</h1>

## ⚠️ Disclaimer

**This project is published strictly for security research, education, and authorized penetration testing.** winDesk is a defensive-minded enumeration framework that wraps well-known, publicly available tools (nmap, NetExec, Impacket, kerbrute, hashcat/john) to help defenders, red teams, and students understand and harden Active Directory environments — the same category as countless open-source security tools hosted on GitHub.

- It is intended **only** for systems you own or are **explicitly authorized in writing** (signed scope / Rules of Engagement) to test, and for study toward certifications such as **OSCP, CRTP, CRTE, CRTO, and CPTS**.
- It performs **no exploitation, no lateral movement, no persistence, and no data exfiltration** — it stops at the point of enumeration/credential access and hands the operator a manual playbook.
- It contains **no malware, no payloads, and no command-and-control functionality**.
- Using it against systems without prior mutual consent is **illegal**. The author assumes **no liability** for misuse or damage.

By using this software you agree to use it lawfully and ethically. If you are not authorized to test a target, **do not point this tool at it.**

---

## Installation

Linux (Kali/Debian/Ubuntu) with **Python 3.8+**.

```bash
git clone https://github.com/ShadiMulla/winDesk.git
cd winDesk
chmod +x install.sh
./install.sh
```

The installer sets up every tool winDesk uses (nmap, netexec, impacket, kerbrute, hashcat/john, certipy, bloodhound-python, ldap3, …). It is re-runnable and skips what's already present.

```bash
./install.sh --check      # report what's installed / missing
./install.sh --no-apt     # pip + kerbrute only
```

Python libraries only:

```bash
pip install -r requirements.txt            # inside a virtualenv
pip install -r requirements.txt --break-system-packages   # modern Kali (PEP 668)
```

Verify:

```bash
python3 winDesk.py --self-test
```

---

## Usage

```bash
python3 winDesk.py <targets> [options]
```

```bash
# Anonymous / null sweep of a subnet
python3 winDesk.py 10.0.0.0/24

# Multiple IPs and a subnet at once
python3 winDesk.py 10.0.0.0/24 192.168.1.5,192.168.1.6

# Userlist → kerbrute user validation + AS-REP roast (no password needed)
python3 winDesk.py 10.0.0.10 --userlist users.txt

# Full no-cred chain → kerbrute + AS-REP + spray + offline crack
python3 winDesk.py 10.0.0.10 --userlist users.txt --passlist passwords.txt

# Spray ONE password across every discovered user (no username given)
python3 winDesk.py 10.0.0.10 -p 'Autumn2025!'

# Authenticated enumeration
python3 winDesk.py 10.0.0.10 -d corp.local -u svc_sql -p 'P@ssw0rd'

# Pass-the-hash (authenticated reads with an NT hash)
python3 winDesk.py 10.0.0.10 -d corp.local -u admin -H aad3b4...:31d6c...

# Stealthy red-team pass against a production subnet
python3 winDesk.py 10.0.0.0/24 --approach stealthy --userlist u.txt --passlist p.txt

# Targets from a file; stop at the first credential
python3 winDesk.py -iL scope.txt --stop-at-access

# Enumeration + playbook only (no roasting / spraying / cracking)
python3 winDesk.py 10.0.0.10 --safe
```

### Common options

```
inputs       -d DOMAIN  -u USER  -p PASS  -H NThash  --userlist FILE  --passlist FILE
approach      --approach {noisy,stealthy}  --safe  --stop-at-access  --quiet-plan
targets       <ip|host|cidr|a.b.c.d-e|comma-list>   -iL FILE
timeouts      --kerbrute-timeout N  --spray-timeout N  --crack-timeout N  (--no-*-timeout to disable)
spray/crack   --force-spray  --no-crack
output        -o DIR  --raw  --no-color
utility       --self-test  --version   (full list: python3 winDesk.py --help)
```

Results are written to `./windesk_out/` as JSON + Markdown reports, plus roasted hashes, cracked `user:password` pairs, and validated usernames.

---

## Version

This is **version 1.0** — the first public release. It works end-to-end, but there is always room for improvement: new techniques, better parsing, more tools, and refinements to the decision engine are planned. Feedback, issues, and pull requests are welcome.

---

**Author:** Shadi Mulla · **License:** [MIT](LICENSE)

winDesk is for lawful, authorized security testing and education only. The author is not responsible for misuse.
