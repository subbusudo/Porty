Python Port Scanner with Web App Fingerprinting and Nmap Integration

This is a fast, multithreaded TCP port scanner written in Python, designed specifically for rapid reconnaissance with a focus on web application security. It includes custom socket logic for HTTP banner grabbing and integrates directly with the industry-standard Nmap tool for deep service version detection.

Key Features

Multithreaded Performance: Utilizes Python's ThreadPoolExecutor to handle concurrent connections, drastically reducing scan time.

Web App Fingerprinting: Automatically performs HTTP HEAD requests on common web ports (80, 443, 8080, etc.) to extract HTTP status codes and the Server banner.

Virtual Host Support: The -H (--host-header) flag allows scanning targets behind load balancers or those using virtual hosting.

Nmap Integration (--nmap-scan): Pipes the list of discovered open ports to Nmap to execute advanced service version detection (-sV) and default script scanning (-sC).

Flexible Port Selection: Supports ranges (1-1024), comma-separated lists (80,443,22), or the fast-track top-ports scan (-F).

Prerequisites

Python 3.x: No external Python libraries are required (only standard library modules are used).

Nmap: The Nmap security scanner binary must be installed on your system and accessible via the system's PATH if you intend to use the --nmap-scan feature.

Usage

Run the scanner from your command line:

python port_scanner.py <target_ip_or_hostname> [options]


Examples

Command

Description

python port_scanner.py 192.168.1.1

Scans default ports 1-1024 with 100 threads.

python port_scanner.py example.com -F

Runs a fast scan against the top 51 common ports.

python port_scanner.py target.net -p 80,443 -H app.vhost.com

Scans ports 80 and 443, explicitly setting the Host header for HTTP checks.

python port_scanner.py 10.10.10.1 -F --nmap-scan -o result.log

Performs a fast scan, saves results to result.log, and then runs a targeted Nmap scan on all open ports found.

Command-line Arguments

# Display help menu
python port_scanner.py --help


Flag

Full Name

Default

Description

target

-

-

The target IP address or hostname.

-p

--ports

1-1024

Ports to scan (e.g., '80,443' or '1-1024').

-F

--fast

False

Scans only the Top 51 common ports.

-H

--host-header

TARGET IP

Sets the Host header for HTTP requests (crucial for virtual hosts).



--user-agent

Standard Chrome UA

Sets a custom User-Agent string for HTTP checks.

-t

--threads

100

Number of concurrent worker threads (max 250).

-w

--wait

1.0

Connection timeout in seconds.

-o

--output

-

Output file to save detailed results.



--nmap-scan

False

Executes a targeted Nmap Service/Script scan on found open ports.
