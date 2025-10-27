⚡ FastPort — Python TCP Port Scanner + Web App Fingerprinting + Nmap Integration ⚡

A lightning-fast, multithreaded TCP port scanner written in pure Python — built for speedy reconnaissance and web app security checks. It does smart HTTP banner grabbing (with virtual host support) and can hand off results to Nmap for deeper service/version/script scanning.

🔥 TL;DR

Blazing fast multi-threaded TCP port scanning.

HTTP HEAD banner grabbing on common web ports (80, 443, 8080, …).

Virtual host support with -H / --host-header.

Pipe discovered ports into Nmap (--nmap-scan) for -sV -sC style discovery.

No external Python packages required — just Python 3.x and (optionally) Nmap installed.

✨ Key Features

Multithreaded performance — ThreadPoolExecutor for concurrent connects.

Web app fingerprinting — automatic HTTP HEAD for status codes & Server headers.

Virtual host (Host:) support — target apps behind load balancers or vhosts.

Flexible port selection — ranges (1-1024), lists (80,443,22) or fast top-ports -F.

Nmap integration — automatically run nmap -sV -sC against discovered ports.

Pure stdlib — no external Python libs required.

🧰 Prerequisites

Python 3.x

If using Nmap integration: Nmap binary must be installed and in your PATH.

🚀 Quick Start
# Default scan (1-1024) with 100 threads
python port_scanner.py 192.168.1.1

# Fast scan (top 51 ports)
python port_scanner.py example.com -F

# Scan specific ports and use Host header
python port_scanner.py target.net -p 80,443 -H app.vhost.com

# Fast scan, save results, then run Nmap on discovered ports
python port_scanner.py 10.10.10.1 -F --nmap-scan -o result.log

📥 Command-line Options (common)
usage: port_scanner.py <target> [options]

-positional:
  target                target IP or hostname

-options:
  -p, --ports           ports: ranges (1-1024), list (80,443), or -F for top-ports
  -t, --threads         number of worker threads (default: 100)
  -H, --host-header     custom Host header for HTTP checks (vhost support)
  -F                    quick scan (top 51 common ports)
  --nmap-scan           run nmap -sV -sC against discovered open ports
  -o, --output          save scan output to file (e.g., result.log)
  -v, --verbose         verbose output (more details per port)
  -h, --help            show help

🔍 What it does (under the hood)

Tries TCP connect to each port using multithreading.

For ports that look like web ports (80, 443, 8080, …), sends an HTTP HEAD request to fetch:

HTTP status code

Server header (banner)

Optional Host: header if -H provided

Collects all open ports and (if --nmap-scan) spawns Nmap to run -sV -sC on those ports for deep fingerprinting.

🧾 Example Output (snip)
[+] 192.168.1.10:22  OPEN  (ssh - OpenSSH_8.4)
[+] 192.168.1.10:80  OPEN  HTTP/1.1 200 OK  Server: nginx/1.18.0
[+] 192.168.1.10:443 OPEN  TLS?  Server: Apache/2.4.41 (Ubuntu)

[INFO] Launching: nmap -sV -sC -p 22,80,443 192.168.1.10

⚠️ Notes & Tips

Nmap integration requires Nmap installed & in PATH. If Nmap is missing, the scanner will still run but will skip deep scans.

Use -H when scanning applications behind load balancers or when the target uses virtual hosts.

Fast scans (-F) are great for quick recon; use full ranges for an exhaustive check.

Running wide scans on infrastructure you don’t own/authorize can be illegal. Always have permission.

🛠️ Contributing

Want to add features (e.g., more HTTP fingerprints, TLS cert parsing, or output formats like JSON)? Pull requests are welcome. Keep contributions focused, well-documented, and backward compatible.

📄 License

MIT — do whatever you want, but please don’t be evil. Attribution appreciated.

If you want, I can:

Add a sleek ASCII/emoji banner for the CLI,

Create JSON/CSV export options, or

Draft a short usage.md with screenshots for a README directory.
