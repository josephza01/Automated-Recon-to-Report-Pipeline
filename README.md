# 🚀 Recon-to-Report Pipeline (`recon.sh`)

A modular, resilient Bash-based reconnaissance pipeline designed to automate initial host discovery, service enumeration, vulnerability assessment, and web content discovery in **Lab/CTF environments**.

Built around Unix pipeline philosophy, `recon.sh` minimizes manual friction by chaining enumeration tools into an automated execution flow with HTML/Log reporting.

---

## 📐 Architecture & Key Principles

### 1. State-Driven Pipeline Chaining
Output from early stages dynamically filters parameters for subsequent phases. For example, Phase 1 full-port scan extracts open ports, which are directly fed into Phase 2 service detection to eliminate redundant probe traffic.

### 2. Operational Resilience & Signal Trapping
Handles interrupts gracefully using POSIX `trap` commands (`SIGINT`/`SIGTERM`) to clean up spawned sub-processes (`nmap`, `ffuf`) and avoid leaving orphan zombie processes in system memory.

### 3. Configurable Environment Variables
Key performance parameters (scan rates, thread counts, timeout limits) are decoupled from the core logic using standard Environment Variables with sane fallback defaults.

---

## 🎯 Alignment with PTES Methodology

The execution sequence directly maps to the **Penetration Testing Execution Standard (PTES)**:

```text
[Target IP]
    │
    ├── ➔ Phase 1: Full TCP Scanning (1-65535)    [PTES: Active Reconnaissance]
    │        └─ Extracted Open Ports
    │
    ├── ➔ Phase 2: Service & Version Detection   [PTES: Service Identification]
    │        └─ Dynamic HTTP/HTTPS Probing
    │
    ├── ➔ Phase 3: Vulnerability Script Scan     [PTES: Vulnerability Analysis]
    │        └─ NSE Script Execution
    │
    ├── ➔ Phase 4: UDP Enumeration                [PTES: Port Scanning]
    │        └─ Top 20 Common UDP Ports
    │
    └── ➔ Phase 5: Web Directory Fuzzing         [PTES: Web Application Recon]
             └─ FFUF Fuzzing (Filtered via Dynamic Scheme Detection)
```

| Pipeline Phase | Method / Tooling | PTES Objective | Output Artifacts |
| :--- | :--- | :--- | :--- |
| **Phase 1: Fast TCP Scan** | `nmap -p- --min-rate` | Active Host Discovery | `1_tcp_full.nmap`, `open_ports.txt` |
| **Phase 2: Service Fingerprinting** | `nmap -sC -sV` | Service Identification & SSL Probing | `2_services.nmap`, `http_ports.txt` |
| **Phase 3: Vuln Assessment** | `nmap --script vuln` | Automated Vulnerability Identification | `3_vuln.nmap`, `3_vuln.html` |
| **Phase 4: UDP Discovery** | `nmap -sU --top-ports 20` | Surface Exposure Analysis | `4_udp.nmap` |
| **Phase 5: Web Fuzzing** | `ffuf` (Context-aware HTTP/S) | Application Pathway Enumeration | `5_web_port_X.json` |

---

## 🛠️ Prerequisites & Installation

Ensure all dependencies are installed on your Kali Linux or Debian-based system:

```bash
sudo apt update
sudo apt install -y nmap ffuf xsltproc gawk coreutils
```

---

## 💻 Usage & Examples

### Basic Execution

```bash
chmod +x recon.sh
./recon.sh <TARGET_IP>
```

### Advanced Usage with Custom Parameters

Override scan rates or thread counts on the fly using environment variables:

```bash
TCP_MIN_RATE=2000 FFUF_THREADS=100 ./recon.sh 10.10.10.10 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

---

## ⚠️ Operational Limitations & Safety Notice

> **Important Disclaimer for Professional Engagements**
>
> While this script provides high speed and convenience for competitive labs (HackTheBox, TryHackMe), **it is NOT intended for direct out-of-the-box use on Production Client Engagements** due to:
>
> 1. **Aggressive Packet Rates (`--min-rate 1000`):** Risks crashing legacy services/OT systems or triggering rate-limits that cause missed ports (False Negatives).
> 2. **Lack of Scope Enforcement:** Does not contain explicit whitelist/blacklist filtering for strict client Rules of Engagement (RoE).
> 3. **Single Target Focus:** Designed for individual IP scanning rather than wide CIDR subnet ranges (`/24`).

---

## 🛣️ Future Roadmap

- [ ] Integrated Web Screenshotting (via `gowitness` or `aquatone`).
- [ ] Subnet / CIDR range support with parallel host scanning.
- [ ] Automated JSON/XML parser to generate a unified Markdown Executive Summary.
- [ ] Safe-Mode preset (`TCP_MIN_RATE=300`) for sensitive targets.

---

## 📜 License

This project is licensed under the **MIT License**. Created for educational purposes and authorized penetration testing in lab environments only.
