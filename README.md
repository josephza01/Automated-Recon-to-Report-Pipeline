# 🚀 Automated Recon-to-Report Pipeline (`recon.sh`)

[![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.style=for-the-badge)](#)
[![Target](https://img.shields.io/badge/Environment-Lab%20%2F%20CTF-orange?style=for-the-badge)](#)

A modular, resilient Bash-based reconnaissance pipeline designed to automate initial host discovery, service enumeration, vulnerability assessment, and web content discovery in **Lab/CTF environments**.

Built around Unix pipeline philosophy, `recon.sh` minimizes manual friction by chaining enumeration tools into an execution flow with automated HTML/Log reporting.

---

## 📐 Architecture & Design Principles

The pipeline is architected around four core design principles:

  1. **State-Driven Pipeline Chaining:**
Output from early stages dynamically filters parameters for subsequent phases (e.g., Phase 1 full-port scan extracts open ports, which are directly fed into Phase 2 service detection to eliminate redundant probe traffic).
  2. **Operational Resilience & Signal Trapping:**
Handles interrupts gracefully using POSIX `trap` commands (`SIGINT`/`SIGTERM`) to clean up spawned sub-processes (`nmap`, `ffuf`) and avoid leaving orphan zombie processes in system memory.
  3. **Twelve-Factor CLI Configurability:**
Key performance parameters (scan rates, thread counts, timeout limits) are decoupled from the core logic using standard Environment Variables with sane fallback defaults.
  4. **Structured Logging & Artifact Isolation:**
All execution logs and converted XML-to-HTML visual reports are grouped per target run using unique timestamped directories.

---

## 🎯 Alignment with PTES Methodology

The execution sequence directly maps to the **Penetration Testing Execution Standard (PTES)** for Intelligence Gathering and Vulnerability Analysis:

[Target IP]
│
├── ➔ Phase 1: Full TCP Scanning (1-65535)    [PTES: Active Reconnaissance]
│        └─ Extracted Open Ports
│
├── ➔ Phase 2: Service & Version Detection   [PTES: Service Identification]
│        └─ Dynamic HTTP/HTTPS Probing
│
├── ➔ Phase 3: Vulnerability Script Scanning  [PTES: Vulnerability Analysis]
│        └─ NSE Script Execution
│
├── ➔ Phase 4: UDP Enumeration                [PTES: Port Scanning]
│        └─ Top 20 Common UDP Ports
│
└── ➔ Phase 5: Web Directory Fuzzing         [PTES: Web Application Recon]
└─ FFUF Fuzzing (Filtered via Dynamic Scheme Detection)

| Pipeline Phase | Method / Tooling | PTES Objective | Output Artifacts |
| :--- | :--- | :--- | :--- |
| **Phase 1: Fast TCP Scan** | `nmap -p- --min-rate` | Active Host Discovery | `1_tcp_full.nmap`, `open_ports.txt` |
| **Phase 2: Service Fingerprinting** | `nmap -sC -sV` | Service Identification & SSL Probing | `2_services.nmap`, `http_ports.txt` |
| **Phase 3: Vuln Assessment** | `nmap --script vuln` | Automated Vulnerability Identification | `3_vuln.nmap`, `3_vuln.html` |
| **Phase 4: UDP Discovery** | `nmap -sU --top-ports 20` | Surface Exposure Analysis | `4_udp.nmap` |
| **Phase 5: Web Fuzzing** | `ffuf` (Context-aware HTTP/S) | Application Pathway Enumeration | `5_web_port_X.json` |

---

## 🛠️ Prerequisites & Dependencies

Ensure the following tools are installed and accessible in your system `$PATH`:

```bash
# Ubuntu / Debian / Kali Linux
sudo apt update && sudo apt install -y nmap ffuf xsltproc gawk coreutils

💻 Usage & Examples
Basic Execution
Bash
chmod +x recon.sh
./recon.sh <TARGET_IP>
