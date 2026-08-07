# recon.sh — Automated Recon Pipeline for Lab Targets

A single-file Bash pipeline that chains the recon phases a pentest methodology
(e.g. **PTES** — Pre-engagement, Intelligence Gathering, Threat Modeling,
Vulnerability Analysis) typically runs by hand: full TCP scan → service/version
detection → NSE vuln scripts → UDP scan → web content fuzzing → web
screenshotting → a Markdown executive summary.

Built for use in an isolated home lab (Kali VM + local target VMs) while
studying penetration testing.

---

## ⚠️ Authorization & Scope — Read This First

**This tool sends active scan traffic (port scans, vuln scripts, directory
fuzzing) to the target.** Running it against a system you don't own or don't
have explicit written permission to test is unauthorized access in most
jurisdictions, regardless of intent.

To reduce the chance of an accidental scan against the wrong host, the script
enforces two guardrails:

| Guardrail | What it does |
|---|---|
| `--confirm` | **Required on every run.** Without it, the script refuses to start. This is a deliberate "yes, I mean to scan this" gate — it is not a technical control, it's a mistake-catcher. |
| Scope check | Before scanning, the script checks whether `TARGET` is a private/lab address (RFC1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback, link-local, CGNAT). If the target is a public-looking IP or an unverifiable hostname, the script **refuses to run** unless `--allow-public` is also passed. |

`--allow-public` does **not** mean "I checked and it's fine" — it means
"I am overriding a safety check I understand." Only use it when you hold a
signed engagement letter / rules of engagement for that specific target.
The script cannot verify authorization for you; it can only slow down
accidental misuse.

---

## Requirements

| Tool | Used for | Required? |
|---|---|---|
| `nmap` | TCP/UDP port scanning, service detection, `--script vuln` | Yes |
| `ffuf` | Web content/directory fuzzing | Yes |
| `xsltproc` | Converting Nmap XML → HTML report | Yes |
| `awk`, `sed`, `grep` | Output parsing | Yes |
| `gowitness` | Web screenshotting (preferred) | No — phase skips if missing |
| `eyewitness` | Web screenshotting (fallback) | No — used only if `gowitness` absent |

On Kali, most of these are preinstalled. Install `gowitness` with:

```bash
go install github.com/sensepost/gowitness@latest
# or, if packaged:
sudo apt install gowitness
```

If neither screenshot tool is present, the pipeline still runs — Phase 6 is
skipped with a warning, and the Markdown summary notes it was skipped.

---

## Usage

```bash
./recon.sh --confirm <TARGET_IP> [WORDLIST_PATH]
./recon.sh --confirm --allow-public <TARGET_HOST_OR_PUBLIC_IP> [WORDLIST_PATH]
./recon.sh --help
```

**Examples**

```bash
# Standard lab target (private IP, no extra flag needed)
./recon.sh --confirm 192.168.56.10

# Target with a custom wordlist
./recon.sh --confirm 192.168.56.10 /usr/share/wordlists/custom.txt

# Public/authorized engagement target — requires explicit override
./recon.sh --confirm --allow-public client-scope.example.com
```

Running without `--confirm`, or against a non-private target without
`--allow-public`, exits with an error before any scanning starts.

### Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `TCP_MIN_RATE` | `1000` | Nmap `--min-rate` for the full TCP scan |
| `UDP_MIN_RATE` | `500` | Nmap `--min-rate` for the UDP scan |
| `FFUF_THREADS` | `50` | ffuf concurrency |
| `FFUF_TIMEOUT` | `10` | ffuf per-request timeout (seconds) |
| `FFUF_MATCH_CODES` | `200,204,301,302,307,401,403` | HTTP status codes ffuf reports |
| `SCREENSHOT_TIMEOUT` | `15` | Per-URL timeout for gowitness/EyeWitness (seconds) |

Example:

```bash
TCP_MIN_RATE=300 FFUF_THREADS=20 ./recon.sh --confirm 192.168.56.10
```

Lower the rates on constrained hardware or slow lab networks to avoid missed
ports from packet loss.

---

## Pipeline Phases

1. **Full TCP scan** (`nmap -p- --min-rate`) — finds every open TCP port.
2. **Service/version detection** (`nmap -sC -sV`) — fingerprints what's
   running on the ports found in Phase 1; also identifies HTTP(S) ports.
3. **Vulnerability scripts** (`nmap --script vuln`) — flags known-CVE
   patterns. **Treat hits as leads, not confirmed findings** — NSE vuln
   scripts have a real false-positive rate.
4. **UDP scan** (top 20 ports) — UDP is slow to scan fully, so this checks
   the ports most commonly worth knowing about (DNS, SNMP, NTP, etc.).
5. **Web content fuzzing** (`ffuf`) — directory/file brute-force against
   every HTTP(S) port found in Phase 2.
6. **Web screenshotting** (`gowitness` / `eyewitness`) — visual snapshot of
   every HTTP(S) service, useful for quickly triaging many hosts/ports.
7. **Executive summary** — a single `EXECUTIVE_SUMMARY.md` pulling the above
   into one readable file: open ports, service table, vuln leads, UDP
   findings, fuzzing hit counts, and a screenshot index.

Each phase degrades gracefully — if a prior phase finds nothing (e.g. no
open ports, no HTTP services), later phases that depend on it are skipped
with a warning rather than failing the whole run.

---

## Output Structure

```
<TARGET>_recon_<TIMESTAMP>/
├── recon.log                    # full run log (also streamed to stdout)
├── open_ports.txt
├── http_ports.txt
├── 1_tcp_full.{nmap,xml,gnmap,html}
├── 2_services.{nmap,xml,gnmap,html}
├── 3_vuln.{nmap,xml,gnmap,html}
├── 4_udp.{nmap,xml,gnmap,html}
├── 5_web_port_<port>.json       # one per HTTP(S) port
├── 6_urls.txt
├── 6_screenshots/
│   └── ... (png files + gowitness.sqlite3, if gowitness was used)
└── EXECUTIVE_SUMMARY.md
```

---

## Known Limitations

Documented deliberately — understanding a tool's blind spots matters as much
as building it:

- **Single target only.** No CIDR/range support; run in a loop for multiple hosts.
- **No client-defined scope file.** The private/public IP heuristic is a
  coarse safety net, not a scope-management system — it can't know about
  out-of-scope hosts *within* a private range.
- **Rate settings are static per run**, not adaptive to packet loss —
  aggressive `--min-rate` values on a lossy network can under-report open ports.
- **NSE vuln scripts produce false positives.** Findings in
  `EXECUTIVE_SUMMARY.md` §3 are leads for manual verification, not
  confirmed vulnerabilities.
- **No cross-phase correlation** — e.g. a CVE found in Phase 3 and a
  fuzzing hit on the same port in Phase 5 aren't automatically linked; a
  human still has to connect them.
- **No JSON/machine-readable summary export** — output is human-readable
  Markdown/HTML, not structured for piping into another tool.

---

## Disclaimer

For use only against systems you own or are explicitly authorized in writing
to test. The author is not responsible for misuse. This project was built
as a learning exercise for penetration testing methodology and Bash scripting.
