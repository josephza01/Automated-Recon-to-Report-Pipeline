#!/usr/bin/env bash
#
# recon.sh - Automated reconnaissance script for lab targets
# Usage: ./recon.sh <TARGET_IP>
#
# Features:
#   - Full TCP/UDP port scanning
#   - Accurate port & HTTP service parsing using awk
#   - Service/version detection & vulnerability scanning
#   - Automatic HTML report generation from Nmap XML (via xsltproc)
#   - Web fuzzing via ffuf

set -euo pipefail

# Color Codes
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

TARGET="${1:-}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [[ -z "$TARGET" ]]; then
    echo -e "${RED}[!] Usage: $0 <TARGET_IP>${NC}"
    exit 1
fi

OUTDIR="${TARGET}_recon_${TIMESTAMP}"
mkdir -p "$OUTDIR"
exec > >(tee -a "$OUTDIR/recon.log") 2>&1

log()  { echo -e "${GREEN}[+] $*${NC}"; }
warn() { echo -e "${YELLOW}[*] $*${NC}"; }
err()  { echo -e "${RED}[-] $*${NC}"; }

run_cmd() {
    local desc="$1"; shift
    log "$desc"
    if "$@"; then
        log "OK: $desc"
    else
        warn "Non-zero exit for: $desc (may be normal)"
    fi
}

banner() {
    echo -e "${CYAN}"
    echo "=============================================="
    echo "  RECON TARGET : $TARGET"
    echo "  TIMESTAMP    : $TIMESTAMP"
    echo "  OUTPUT DIR   : $OUTDIR"
    echo "=============================================="
    echo -e "${NC}"
}

check_tools() {
    local missing=0
    for tool in nmap ffuf xsltproc; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            err "Missing required tool: $tool"
            missing=1
        fi
    done
    if (( missing )); then
        err "Install missing tools: sudo apt install -y nmap ffuf xsltproc"
        exit 1
    fi
}

generate_html_report() {
    local xml_file="$1"
    local html_file="${xml_file%.xml}.html"

    if [[ ! -f "$xml_file" ]]; then
        warn "XML file not found for HTML conversion: $xml_file"
        return
    fi

    log "Generating HTML report: $(basename "$html_file")"

    local bootstrap_xsl="/usr/share/nmap/nmap-bootstrap.xsl"
    if [[ -f "$bootstrap_xsl" ]]; then
        xsltproc "$bootstrap_xsl" "$xml_file" -o "$html_file" || warn "Failed to convert using Bootstrap XSL"
    else
        xsltproc "$xml_file" -o "$html_file" || warn "Failed to convert using default XSL"
    fi

    if [[ -f "$html_file" ]]; then
        log "HTML report created successfully: $html_file"
    fi
}

phase1_tcp() {
    log "Phase 1: Full TCP port scan (all 65535 ports)"
    nmap -Pn -p- --min-rate 1000 -oA "$OUTDIR/1_tcp_full" "$TARGET" || true

    # Accurate port extraction from .gnmap
    OPEN_PORTS=$(awk '/Ports:/{
        for (i=1; i<=NF; i++) {
            if ($i ~ /\/open\//) {
                split($i, a, "/");
                printf "%s,", a[1]
            }
        }
    }' "$OUTDIR/1_tcp_full.gnmap" | sed 's/,$//')

    if [[ -n "${OPEN_PORTS:-}" ]]; then
        log "Open TCP ports: $OPEN_PORTS"
        echo "$OPEN_PORTS" > "$OUTDIR/open_ports.txt"
    else
        warn "No open TCP ports found."
    fi

    generate_html_report "$OUTDIR/1_tcp_full.xml"
}

phase2_services() {
    if [[ -z "${OPEN_PORTS:-}" ]]; then return; fi
    log "Phase 2: Service + version detection (nmap -sC -sV)"
    run_cmd "Service scan on $OPEN_PORTS" \
        nmap -Pn -sC -sV -p "$OPEN_PORTS" -oA "$OUTDIR/2_services" "$TARGET"

    generate_html_report "$OUTDIR/2_services.xml"

    # Accurate HTTP/HTTPS service extraction from .gnmap
    HTTP_PORTS=$(awk '/Ports:/{
        for (i=1; i<=NF; i++) {
            if ($i ~ /\/open\/tcp\/\/(http|https|ssl\|http)/) {
                split($i, a, "/");
                printf "%s\n", a[1]
            }
        }
    }' "$OUTDIR/2_services.gnmap" | sort -u | tr '\n' ' ')

    if [[ -n "${HTTP_PORTS:-}" ]]; then
        log "HTTP/HTTPS services found on ports: $HTTP_PORTS"
        echo "$HTTP_PORTS" > "$OUTDIR/http_ports.txt"
    else
        warn "No obvious HTTP/HTTPS services found."
    fi
}

phase3_vuln() {
    if [[ -z "${OPEN_PORTS:-}" ]]; then return; fi
    log "Phase 3: Vulnerability script scan"
    run_cmd "Vuln script scan" \
        nmap -Pn --script vuln -p "$OPEN_PORTS" -oA "$OUTDIR/3_vuln" "$TARGET"

    generate_html_report "$OUTDIR/3_vuln.xml"
}

phase4_udp() {
    log "Phase 4: UDP scan on common services"
    run_cmd "UDP scan" \
        nmap -Pn -sU --top-ports 20 --min-rate 500 -oA "$OUTDIR/4_udp" "$TARGET"

    generate_html_report "$OUTDIR/4_udp.xml"
}

phase5_web() {
    if [[ -z "${HTTP_PORTS:-}" ]]; then return; fi
    log "Phase 5: Web content fuzzing with ffuf"

    WORDLIST="${WORDLIST:-/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt}"
    if [[ ! -f "$WORDLIST" ]]; then
        WORDLIST=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    fi
    if [[ ! -f "$WORDLIST" ]]; then
        warn "No wordlist found; skipping ffuf. Set WORDLIST env var to your own."
        return
    fi
    warn "Using wordlist: $WORDLIST"

    for port in $HTTP_PORTS; do
        scheme="http"
        if grep -qi "ssl/http\|https" "$OUTDIR/2_services.nmap" && [[ "$port" =~ ^(443|8443|9443)$ ]]; then
            scheme="https"
        fi
        url="${scheme}://${TARGET}:${port}"
        log "Fuzzing $url with ffuf"
        ffuf -u "$url/FUZZ" -w "$WORDLIST" \
             -ac -c -t 50 --timeout 10 -mc 200,204,301,302,307,401,403 \
             -o "$OUTDIR/5_web_port_${port}.json" || true
    done
}

summary() {
    echo -e "${CYAN}"
    echo "=============================================="
    echo "  RECON COMPLETE"
    echo "  Output saved to: $OUTDIR"
    echo "=============================================="
    echo -e "${NC}"
    ls -1 "$OUTDIR"
}