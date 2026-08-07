#!/usr/bin/env bash
#
# recon.sh - Automated reconnaissance pipeline for lab targets
# Usage: ./recon.sh <TARGET_IP> [WORDLIST_PATH]
#

set -euo pipefail

# ==========================================
# CONFIGURATION & CONFIGURABLE DEFAULTS
# ==========================================
# สามารถ Override ค่าเหล่านี้ได้ผ่าน Environment Variables
TCP_MIN_RATE="${TCP_MIN_RATE:-1000}"
UDP_MIN_RATE="${UDP_MIN_RATE:-500}"
FFUF_THREADS="${FFUF_THREADS:-50}"
FFUF_TIMEOUT="${FFUF_TIMEOUT:-10}"
FFUF_MATCH_CODES="${FFUF_MATCH_CODES:-200,204,301,302,307,401,403}"
SCREENSHOT_TIMEOUT="${SCREENSHOT_TIMEOUT:-15}"

DEFAULT_WORDLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
FALLBACK_WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

# Color Palette
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

# ==========================================
# ARGUMENT PARSING (supports flags anywhere)
# ==========================================
CONFIRM=0
ALLOW_PUBLIC=0
POSITIONAL=()

print_usage() {
    cat <<EOF
Usage: $0 --confirm [--allow-public] <TARGET_IP> [WORDLIST_PATH]

Required:
  --confirm         Explicitly confirm you are authorized to test TARGET.
                     The script refuses to run without this flag.

Optional:
  --allow-public     Allow scanning a target OUTSIDE private/RFC1918 lab
                     ranges (or a hostname that can't be scope-verified).
                     Only use this with EXPLICIT WRITTEN AUTHORIZATION
                     (e.g. a signed pentest engagement / rules of engagement).
  -h, --help         Show this help message.

Examples:
  $0 --confirm 192.168.56.10
  $0 --confirm --allow-public client-scope.example.com wordlist.txt
EOF
}

for arg in "$@"; do
    case "$arg" in
        --confirm)      CONFIRM=1 ;;
        --allow-public) ALLOW_PUBLIC=1 ;;
        -h|--help)      print_usage; exit 0 ;;
        *)              POSITIONAL+=("$arg") ;;
    esac
done

# Target & Wordlist Arguments
TARGET="${POSITIONAL[0]:-}"
WORDLIST="${POSITIONAL[1]:-${WORDLIST:-$DEFAULT_WORDLIST}}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ==========================================
# SIGNAL HANDLING & TRAP CLEANUP
# ==========================================
cleanup() {
    echo -e "\n${RED}[!] Process interrupted (SIGINT/SIGTERM). Cleaning up child jobs...${NC}"
    # สั่ง Kill Process ลูกทั้งหมดที่รันอยู่ภายใต้ Subshell
    kill $(jobs -p) 2>/dev/null || true
    exit 130
}

# ดักจับ Signal การยกเลิก (Ctrl+C หรือ kill command)
trap cleanup SIGINT SIGTERM

# ==========================================
# HELPER FUNCTIONS
# ==========================================
log()  { echo -e "${GREEN}[+] $*${NC}"; }
warn() { echo -e "${YELLOW}[*] $*${NC}"; }
err()  { echo -e "${RED}[-] $*${NC}"; }

banner() {
    echo -e "${CYAN}"
    echo "=============================================="
    echo "  RECON TARGET   : $TARGET"
    echo "  TIMESTAMP      : $TIMESTAMP"
    echo "  OUTPUT DIR     : ${OUTDIR:-N/A}"
    echo "  AUTHORIZED     : $([[ $CONFIRM -eq 1 ]] && echo 'YES (--confirm)' || echo 'NO')"
    echo "  ALLOW-PUBLIC   : $([[ $ALLOW_PUBLIC -eq 1 ]] && echo 'YES' || echo 'NO (lab-scope only)')"
    echo "=============================================="
    echo -e "${NC}"
}

check_deps() {
    local missing=0
    for tool in nmap ffuf xsltproc awk sed grep; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            err "Missing required tool: $tool"
            missing=1
        fi
    done
    if (( missing )); then
        err "Please install missing tools before running."
        exit 1
    fi

    # Screenshot tools are optional - just warn, don't hard-fail the pipeline
    if ! command -v gowitness >/dev/null 2>&1 && ! command -v eyewitness >/dev/null 2>&1; then
        warn "Neither 'gowitness' nor 'eyewitness' found. Phase 6 (screenshots) will be skipped."
        warn "Install with: go install github.com/sensepost/gowitness@latest  (or)  apt install eyewitness"
    fi
}

run_cmd() {
    local desc="$1"; shift
    log "$desc"
    if "$@"; then
        log "OK: $desc"
    else
        warn "Non-zero exit status for: $desc (may be normal)"
    fi
}

generate_html_report() {
    local xml_file="$1"
    local html_file="${xml_file%.xml}.html"

    if [[ ! -f "$xml_file" ]]; then
        warn "XML file not found for HTML conversion: $xml_file"
        return
    fi

    local bootstrap_xsl="/usr/share/nmap/nmap-bootstrap.xsl"
    if [[ -f "$bootstrap_xsl" ]]; then
        xsltproc "$bootstrap_xsl" "$xml_file" -o "$html_file" 2>/dev/null || \
        xsltproc "$xml_file" -o "$html_file" || warn "HTML conversion failed for $xml_file"
    else
        xsltproc "$xml_file" -o "$html_file" || warn "HTML conversion failed for $xml_file"
    fi

    [[ -f "$html_file" ]] && log "HTML report created: $(basename "$html_file")"
}

# ตรวจสอบ HTTPS รายพอร์ตจาก Nmap Output โดยตรง
is_https_port() {
    local port="$1"
    local services_file="$OUTDIR/2_services.nmap"

    if [[ ! -f "$services_file" ]]; then
        return 1
    fi

    # ค้นหาบรรทัดของพอร์ตนั้นๆ และเช็คว่ามีคำว่า ssl, https หรือ tls หรือไม่
    awk -v p="$port" '
        $1 ~ "^"p"/tcp" {
            if ($0 ~ /(ssl|https|tls)/) {
                found=1
            }
        }
        END { exit !found }
    ' "$services_file"
}

# ==========================================
# AUTHORIZATION & SCOPE GUARDRAILS
# ==========================================
# ตรวจสอบว่า target อยู่ใน private/lab range หรือไม่ (RFC1918 + loopback + link-local + CGN)
# Return: 0 = private/lab range, 1 = public-looking IP, 2 = not a valid IPv4 (likely hostname)
is_private_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        return 2
    fi
    local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}"
    (( o1 == 10 )) && return 0                              # 10.0.0.0/8
    (( o1 == 172 && o2 >= 16 && o2 <= 31 )) && return 0      # 172.16.0.0/12
    (( o1 == 192 && o2 == 168 )) && return 0                 # 192.168.0.0/16
    (( o1 == 127 )) && return 0                               # 127.0.0.0/8 loopback
    (( o1 == 169 && o2 == 254 )) && return 0                 # 169.254.0.0/16 link-local
    (( o1 == 100 && o2 >= 64 && o2 <= 127 )) && return 0     # 100.64.0.0/10 CGN
    return 1
}

scope_check() {
    is_private_ip "$TARGET"
    local rc=$?

    if (( rc == 0 )); then
        log "Scope check: '$TARGET' is within a private/lab IP range (RFC1918/loopback/link-local/CGN)."
        return
    fi

    if (( rc == 2 )); then
        warn "Scope check: '$TARGET' is not a plain IPv4 address (looks like a hostname)."
        warn "Cannot automatically verify this target is in-scope."
    else
        warn "Scope check: '$TARGET' looks like a PUBLIC IP address (outside RFC1918 lab ranges)."
    fi

    if (( ALLOW_PUBLIC == 0 )); then
        err "Refusing to proceed. This target could not be auto-verified as a private/lab address."
        err "If you have EXPLICIT WRITTEN AUTHORIZATION to test this target, re-run with --allow-public."
        exit 1
    else
        warn "Proceeding because --allow-public was specified."
        warn "YOU are responsible for confirming written authorization / rules of engagement for '$TARGET'."
    fi
}

authorization_gate() {
    if (( CONFIRM == 0 )); then
        err "Refusing to run: missing required --confirm flag."
        err "--confirm asserts that you are authorized to run active scans against '$TARGET'."
        echo ""
        print_usage
        exit 1
    fi
    log "Authorization confirmed via --confirm for target: $TARGET"
}

# ==========================================
# INITIALIZATION & PIPELINE PHASES
# ==========================================

if [[ -z "$TARGET" ]]; then
    err "Usage: $0 --confirm [--allow-public] <TARGET_IP> [WORDLIST_PATH]"
    err "Run '$0 --help' for details."
    exit 1
fi

authorization_gate
scope_check
check_deps

OUTDIR="${TARGET}_recon_${TIMESTAMP}"
mkdir -p "$OUTDIR"

# Redirect stdout/stderr ไปยัง log file พร้อมแสดงบนหน้าจอ
exec > >(tee -a "$OUTDIR/recon.log") 2>&1

banner

phase1_tcp() {
    log "Phase 1: Full TCP Port Scan (Ports 1-65535)"
    nmap -Pn -p- --min-rate "$TCP_MIN_RATE" -oA "$OUTDIR/1_tcp_full" "$TARGET" || true

    OPEN_PORTS=$(awk '/Ports:/{
        for (i=1; i<=NF; i++) {
            if ($i ~ /\/open\//) {
                split($i, a, "/");
                printf "%s,", a[1]
            }
        }
    }' "$OUTDIR/1_tcp_full.gnmap" | sed 's/,$//')

    if [[ -n "${OPEN_PORTS:-}" ]]; then
        log "Open TCP Ports: $OPEN_PORTS"
        echo "$OPEN_PORTS" > "$OUTDIR/open_ports.txt"
    else
        warn "No open TCP ports found."
    fi

    generate_html_report "$OUTDIR/1_tcp_full.xml"
}

phase2_services() {
    if [[ -z "${OPEN_PORTS:-}" ]]; then
        warn "Skipping Phase 2: No open TCP ports detected."
        return
    fi

    log "Phase 2: Service & Version Detection (nmap -sC -sV)"
    run_cmd "Service Fingerprinting" \
        nmap -Pn -sC -sV -p "$OPEN_PORTS" -oA "$OUTDIR/2_services" "$TARGET"

    generate_html_report "$OUTDIR/2_services.xml"

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
        warn "No HTTP/HTTPS services found."
    fi
}

phase3_vuln() {
    if [[ -z "${OPEN_PORTS:-}" ]]; then return; fi
    log "Phase 3: Vulnerability Script Scan (--script vuln)"
    run_cmd "Vuln Scan" \
        nmap -Pn --script vuln -p "$OPEN_PORTS" -oA "$OUTDIR/3_vuln" "$TARGET"

    generate_html_report "$OUTDIR/3_vuln.xml"
}

phase4_udp() {
    log "Phase 4: UDP Scan (Top 20 Ports)"
    run_cmd "UDP Scan" \
        nmap -Pn -sU --top-ports 20 --min-rate "$UDP_MIN_RATE" -oA "$OUTDIR/4_udp" "$TARGET"

    generate_html_report "$OUTDIR/4_udp.xml"
}

phase5_web() {
    if [[ -z "${HTTP_PORTS:-}" ]]; then
        warn "Skipping Phase 5: No HTTP/HTTPS services available."
        return
    fi

    log "Phase 5: Web Content Fuzzing (ffuf)"

    if [[ ! -f "$WORDLIST" ]]; then
        WORDLIST="$FALLBACK_WORDLIST"
    fi

    if [[ ! -f "$WORDLIST" ]]; then
        warn "No wordlist found at default locations. Skipping ffuf."
        return
    fi

    log "Using wordlist: $WORDLIST"

    for port in $HTTP_PORTS; do
        scheme="http"
        if is_https_port "$port"; then
            scheme="https"
            log "Port $port: Detected SSL/HTTPS"
        else
            log "Port $port: Detected HTTP"
        fi

        url="${scheme}://${TARGET}:${port}"
        log "Fuzzing $url with ffuf"

        ffuf -u "$url/FUZZ" -w "$WORDLIST" \
             -ac -c -t "$FFUF_THREADS" --timeout "$FFUF_TIMEOUT" \
             -mc "$FFUF_MATCH_CODES" \
             -o "$OUTDIR/5_web_port_${port}.json" || true
    done
}

# ==========================================
# PHASE 6: WEB SCREENSHOTTING
# ==========================================
# สร้างไฟล์รายชื่อ URL จาก HTTP_PORTS แล้วส่งให้ gowitness / eyewitness
# ถ่ายภาพหน้าเว็บของแต่ละพอร์ตที่เจอ เก็บไว้ใน $OUTDIR/6_screenshots
phase6_screenshot() {
    if [[ -z "${HTTP_PORTS:-}" ]]; then
        warn "Skipping Phase 6: No HTTP/HTTPS services available."
        return
    fi

    if ! command -v gowitness >/dev/null 2>&1 && ! command -v eyewitness >/dev/null 2>&1; then
        warn "Skipping Phase 6: no screenshot tool (gowitness/eyewitness) installed."
        return
    fi

    log "Phase 6: Web Screenshotting"

    local shot_dir="$OUTDIR/6_screenshots"
    mkdir -p "$shot_dir"

    # สร้างไฟล์ URL list (ใช้ต่อทั้ง gowitness และ eyewitness)
    local url_list="$OUTDIR/6_urls.txt"
    : > "$url_list"
    for port in $HTTP_PORTS; do
        scheme="http"
        is_https_port "$port" && scheme="https"
        echo "${scheme}://${TARGET}:${port}" >> "$url_list"
    done

    if command -v gowitness >/dev/null 2>&1; then
        log "Using gowitness for screenshots"
        # gowitness v3 syntax: 'gowitness scan file -f urls.txt'
        # เก็บ screenshot png + sqlite db ไว้ใน shot_dir
        if gowitness scan file \
                -f "$url_list" \
                --screenshot-path "$shot_dir" \
                --write-db --write-db-uri "sqlite://$shot_dir/gowitness.sqlite3" \
                --timeout "$SCREENSHOT_TIMEOUT" 2>/dev/null; then
            log "OK: gowitness screenshots saved to $shot_dir"
        else
            # Fallback flags สำหรับ gowitness v2 ที่ syntax ต่างกัน
            warn "gowitness v3 syntax failed, retrying with legacy (v2) syntax..."
            run_cmd "gowitness (legacy syntax)" \
                gowitness file -f "$url_list" -P "$shot_dir" --timeout "$SCREENSHOT_TIMEOUT"
        fi
    elif command -v eyewitness >/dev/null 2>&1; then
        log "Using EyeWitness for screenshots"
        run_cmd "EyeWitness" \
            eyewitness --web -f "$url_list" -d "$shot_dir" --no-prompt --timeout "$SCREENSHOT_TIMEOUT"
    fi

    # นับจำนวนไฟล์ภาพที่ถ่ายได้สำเร็จ
    SCREENSHOT_COUNT=$(find "$shot_dir" -type f \( -iname '*.png' -o -iname '*.jpeg' -o -iname '*.jpg' \) 2>/dev/null | wc -l)
    log "Screenshots captured: $SCREENSHOT_COUNT"
}

# ==========================================
# EXECUTIVE SUMMARY (MARKDOWN REPORT)
# ==========================================
# รวบรวมผลจากทุก Phase มาสรุปเป็นไฟล์ Markdown อ่านง่าย
# เหมาะสำหรับแนบไปกับรายงาน หรือ paste ลง Obsidian/Notion
generate_markdown_report() {
    log "Generating Executive Summary (Markdown)"

    local report="$OUTDIR/EXECUTIVE_SUMMARY.md"
    local open_ports_display="N/A"
    local http_ports_display="N/A"

    [[ -f "$OUTDIR/open_ports.txt" ]] && open_ports_display=$(cat "$OUTDIR/open_ports.txt")
    [[ -f "$OUTDIR/http_ports.txt" ]] && http_ports_display=$(cat "$OUTDIR/http_ports.txt")

    {
        echo "# Recon Executive Summary"
        echo ""
        echo "| Field | Value |"
        echo "|---|---|"
        echo "| Target | \`$TARGET\` |"
        echo "| Scan Date | $TIMESTAMP |"
        echo "| Output Directory | \`$OUTDIR\` |"
        echo "| Authorized (--confirm) | $([[ $CONFIRM -eq 1 ]] && echo 'Yes' || echo 'No') |"
        echo "| Allow-Public Scope | $([[ $ALLOW_PUBLIC -eq 1 ]] && echo 'Yes' || echo 'No (lab-range only)') |"
        echo ""
        echo "---"
        echo ""

        # --- Open Ports ---
        echo "## 1. Open TCP Ports"
        echo ""
        if [[ "$open_ports_display" != "N/A" ]]; then
            echo "\`\`\`"
            echo "$open_ports_display"
            echo "\`\`\`"
        else
            echo "_No open TCP ports detected._"
        fi
        echo ""

        # --- Services table (parsed from nmap -sV greppable/normal output) ---
        echo "## 2. Services Detected"
        echo ""
        if [[ -f "$OUTDIR/2_services.nmap" ]]; then
            echo "| Port/Proto | State | Service | Version |"
            echo "|---|---|---|---|"
            # แปลงบรรทัดแบบ "22/tcp   open  ssh   OpenSSH 8.4"
            grep -E '^[0-9]+/(tcp|udp)' "$OUTDIR/2_services.nmap" | \
            awk '{
                port=$1; state=$2; svc=$3;
                $1=""; $2=""; $3="";
                ver=$0;
                sub(/^ +/, "", ver);
                printf "| %s | %s | %s | %s |\n", port, state, svc, (ver=="" ? "-" : ver)
            }'
        else
            echo "_Service detection was skipped or produced no output._"
        fi
        echo ""

        # --- Vulnerabilities found ---
        echo "## 3. Vulnerability Scan Findings"
        echo ""
        if [[ -f "$OUTDIR/3_vuln.nmap" ]]; then
            local vuln_hits
            vuln_hits=$(grep -iE 'VULNERABLE|CVE-[0-9]{4}-[0-9]+' "$OUTDIR/3_vuln.nmap" || true)
            if [[ -n "$vuln_hits" ]]; then
                echo "> ⚠️ Potential findings below — **verify manually**, nmap NSE vuln scripts can false-positive."
                echo ""
                echo "\`\`\`"
                echo "$vuln_hits"
                echo "\`\`\`"
            else
                echo "_No VULNERABLE flags or CVE references found by NSE scripts._"
            fi
        else
            echo "_Vulnerability scan was skipped or produced no output._"
        fi
        echo ""

        # --- UDP summary ---
        echo "## 4. UDP Scan (Top 20 Ports)"
        echo ""
        if [[ -f "$OUTDIR/4_udp.nmap" ]]; then
            local udp_open
            udp_open=$(grep -E '^[0-9]+/udp.*open' "$OUTDIR/4_udp.nmap" || true)
            if [[ -n "$udp_open" ]]; then
                echo "\`\`\`"
                echo "$udp_open"
                echo "\`\`\`"
            else
                echo "_No open UDP ports found in top 20._"
            fi
        else
            echo "_UDP scan was skipped or produced no output._"
        fi
        echo ""

        # --- HTTP / Fuzzing ---
        echo "## 5. Web Services & Content Discovery"
        echo ""
        if [[ "$http_ports_display" != "N/A" ]]; then
            echo "HTTP/HTTPS detected on ports: \`$http_ports_display\`"
            echo ""
            for f in "$OUTDIR"/5_web_port_*.json; do
                [[ -f "$f" ]] || continue
                local port_num
                port_num=$(basename "$f" | sed -E 's/5_web_port_([0-9]+)\.json/\1/')
                local hit_count
                hit_count=$(grep -o '"status"' "$f" 2>/dev/null | wc -l)
                echo "- Port \`$port_num\`: $hit_count matched path(s) — see \`$(basename "$f")\`"
            done
        else
            echo "_No HTTP/HTTPS services were available for fuzzing._"
        fi
        echo ""

        # --- Screenshots ---
        echo "## 6. Web Screenshots"
        echo ""
        local shot_dir="$OUTDIR/6_screenshots"
        if [[ -d "$shot_dir" ]]; then
            local shots=()
            while IFS= read -r -d '' f; do shots+=("$f"); done < \
                <(find "$shot_dir" -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' \) -print0 2>/dev/null)

            if (( ${#shots[@]} > 0 )); then
                echo "${#shots[@]} screenshot(s) captured in \`$shot_dir\`:"
                echo ""
                for s in "${shots[@]}"; do
                    echo "- \`$(basename "$s")\`"
                done
            else
                echo "_Screenshot tool ran but no images were captured (targets may have been unreachable)._"
            fi
        else
            echo "_Phase 6 was skipped (no screenshot tool installed, or no HTTP services)._"
        fi
        echo ""

        echo "---"
        echo ""
        echo "_Generated automatically by recon.sh — treat all findings as leads requiring manual verification, not confirmed conclusions._"

    } > "$report"

    log "Executive summary written: $(basename "$report")"
}

summary() {
    echo -e "${CYAN}"
    echo "=============================================="
    echo "  RECON PIPELINE COMPLETE"
    echo "  Output Directory : $OUTDIR"
    echo "  Log File         : $OUTDIR/recon.log"
    echo "  Summary Report   : $OUTDIR/EXECUTIVE_SUMMARY.md"
    echo "=============================================="
    echo -e "${NC}"
    ls -lh "$OUTDIR"
}

# ==========================================
# PIPELINE EXECUTION
# ==========================================
phase1_tcp
phase2_services
phase3_vuln
phase4_udp
phase5_web
phase6_screenshot
generate_markdown_report
summary
