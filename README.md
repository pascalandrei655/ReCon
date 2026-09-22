# ReCon — Modular Network Scanner & CVE Vulnerability Matcher

**ReCon** is a modular Python-based security auditing framework designed to automate asset discovery, banner grabbing, service fingerprinting, and vulnerability matching. It bridges network reconnaissance with real-world threat analysis by automatically translating service banners into Common Platform Enumerations (CPE) and querying the NIST National Vulnerability Database (NVD) for active CVEs.

---

## Key Features

- **Port Scanner (`rescan`):** Fast multi-threaded TCP/UDP port scanner supporting custom port ranges, timing profiles (stealth to aggressive), and flexible target input formats (IP, CIDR, hostname).
- **Banner Grabber (`rebanner`):** Protocol-aware service fingerprinting for common ports (HTTP/S, SSH, FTP, SMTP, MySQL, SMB, Telnet).
- **Vulnerability Matcher (`rematcher`):**
    - Parses raw banners into structured Product and Version components.
    - Dynamically generates CPE identifiers (`cpe:2.3:a:...`).
    - Queries the NIST NVD API v2.0 to extract relevant CVEs and CVSS v3/v4 metrics.
    - Supports fine-grained filtering based on CVSS attack vectors (Network, Local), privileges required, and interaction complexity.
- **Flexible Logging:** Direct console output with optional plain-text file export ( `o / --output`).

---

## Prerequisites & Installation

### Requirements

- Python 3.10 or higher
- Valid NIST NVD API Key (recommended to avoid API rate limits)

### Setup Instructions

1. **Clone the repository:**
    
    ```bash
    git clone "https://github.com/pascalandrei655/recon.git"
    cd recon
    ```
    
2. **Create and activate a virtual environment:**
    - **Linux / macOS:**
        
        ```
        python3 -m venv venv
        source venv/bin/activate
        ```
        
    - **Windows (PowerShell):**
        
        ```
        python -m venv venv
        .\venv\Scripts\Activate.ps1
        ```
        
3. **Install dependencies:**
    
    ```
    pip install -r requirements.txt
    ```
    
4. **Environment Variables:**
Create a `.env` file in the root directory and add your NVD API Key:
    
    ```
    NVD_API_KEY=your_api_key_here
    ```
    

---

## Usage Examples

### 1. Port Scanning

Scan top 100 ports on a target IP with stealth timing profile:

```
python rescan.py -H 192.168.1.10 -p 1-100 -t 1 -o scan_results.txt
```

### 2. Banner Grabbing

Extract service banners from identified open ports:

```
python rebanner.py -H 192.168.1.10 -p 22,80,3306 -o banners.txt
```

### 3. Vulnerability Matching

Perform full banner-to-CVE resolution with CVSS filtering:

```
python rematcher.py -H 192.168.1.10 -p 22,80,3306 --attack-vector NETWORK --vuln-count 5 -o cve_report.txt
```

---

## ⚙️ Architecture Pipeline

```
[ Target Input ] ➔ [ Port Scanner ] ➔ [ Banner Grabber ] ➔ [ CPE Parser ] ➔ [ NVD API Matcher ] ➔ [ Results / Export ]
```

---

## ⚠️ Legal & Ethical Disclaimer

**This tool is developed strictly for authorized security testing, educational purposes, and defensive research.**

- **Authorized Testing Only:** Scanning systems or networks without explicit, written permission from the owner is illegal and violates local, national, and international cybercrime laws (e.g., the U.S. Computer Fraud and Abuse Act, EU Directive 2013/40/EU, and GDPR).
- **No Liability:** The developer(s) of this project assume **no liability or responsibility** for any misuse, damage, data loss, or unlawful activities conducted with this software.
- **User Compliance:** It is the end user's sole responsibility to ensure all actions strictly comply with applicable laws in their jurisdiction prior to running any operational modules.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.