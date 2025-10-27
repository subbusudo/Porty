import socket
import argparse
import time
import subprocess 
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
# Maximum number of concurrent threads
MAX_WORKERS = 250
# Default timeout for socket connection attempts (in seconds)
DEFAULT_CONNECT_TIMEOUT = 1.0
# Short timeout for service banner grabbing
BANNER_GRAB_TIMEOUT = 0.5
# Default ports to scan if none are specified
DEFAULT_PORTS_ARG = "1-1024"

# Nmap Command template: Use -sV (Service Version) and -sC (Default Scripts)
NMAP_BASE_CMD = "nmap -sV -sC"

# Standard IANA assignments for basic identification
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP Proxy", 20: "FTP-Data", 1521: "Oracle", 8443: "HTTPS-Alt"
}

# Ports where an HTTP check should be performed (web app focus)
WEB_PORTS = {80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 9090}

# Top ports for the creative Fast-Track Scan (-F)
TOP_PORTS = sorted(list({
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1720, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 20, 161, 162,
    500, 1080, 1433, 1434, 1521, 2000, 2049, 2121, 25565, 3000,
    3128, 4000, 5000, 5001, 5800, 5985, 5986, 6000, 6379, 8000,
    8081, 8888, 9000, 9090, 10000, 27017
}))


def parse_port_range(port_arg):
    """
    Parses port input, which can be a single port (80), a range (1-1024), or comma-separated lists.
    Returns a list of valid port integers.
    """
    ports = set()
    try:
        # Handle comma-separated list
        parts = port_arg.split(',')
        
        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end:
                    raise ValueError("Start port cannot be greater than end port.")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part.strip())) # .strip() handles spaces if present

    except ValueError as e:
        print(f"[ERROR] Invalid port specification: {e}")
        return []

    # Filter for valid ports (1-65535)
    valid_ports = [p for p in ports if 1 <= p <= 65535]
    return sorted(valid_ports)


def get_http_status_and_banner(s, target_ip, port, host_header, user_agent):
    """
    Sends a HEAD request to extract HTTP status and server banner.
    Returns a string containing the detailed info.
    """
    s.settimeout(BANNER_GRAB_TIMEOUT)
    try:
        # Construct a simple HTTP HEAD request
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode('ascii')
        
        s.sendall(request)
        
        # Read the response (up to 4KB)
        response_data = s.recv(4096).decode('utf-8', errors='ignore')
        
        if not response_data:
            return "HTTP: No response received after HEAD request."
            
        # Extract the first line (Status Line)
        first_line = response_data.splitlines()[0]
        if first_line.startswith("HTTP/"):
            # Extract status code (e.g., "HTTP/1.1 200 OK")
            http_status = " ".join(first_line.split(" ")[1:])
            
            # Look for Server header in the response
            server_banner = "Server: Unknown"
            for line in response_data.splitlines():
                if line.lower().startswith('server:'):
                    server_banner = line.strip()
                    break
            
            return f"HTTP Status: {http_status} | {server_banner}"
        
        # If it's not HTTP, just grab the initial banner data
        return f"Service Banner: {response_data.splitlines()[0][:100]}"
        
    except socket.timeout:
        return "HTTP Check: Request timed out."
    except Exception as e:
        return f"HTTP Check Error: {type(e).__name__}"


def get_generic_banner(s, port):
    """
    Performs standard service banner grabbing for non-HTTP ports.
    """
    s.settimeout(BANNER_GRAB_TIMEOUT)
    service_name = COMMON_PORTS.get(port, "Unknown")
    try:
        # Try to receive data passively (many services send a banner immediately)
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if banner:
            return f"{service_name}: {banner.splitlines()[0][:100]}"
        
        return f"{service_name}: No explicit banner."

    except socket.timeout:
        return f"{service_name}: Banner grab timed out."
    except Exception as e:
        return f"{service_name}: Error during banner grab ({type(e).__name__})."


def scan_port(host, port, timeout, host_header, user_agent):
    """
    Attempts a TCP connection scan (-sT) and determines service info.
    Returns (port, status, service_info). Status is 'open', 'closed', or 'filtered'.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        # 1. Attempt connection (TCP Connect Scan)
        s.connect((host, port))
        
        # 2. Connection successful, perform advanced service detection
        if port in WEB_PORTS:
            service_info = get_http_status_and_banner(s, host, port, host_header, user_agent)
        else:
            service_info = get_generic_banner(s, port)
            
        return port, 'open', service_info

    except ConnectionRefusedError:
        # The port sent an RST packet (Reset), meaning it's actively closed.
        return port, 'closed', ""
    except socket.timeout:
        # Timed out, suggesting a firewall or network issue.
        return port, 'filtered', ""
    except Exception as e:
        # Catch network unreachable, permissions errors, etc.
        return port, 'error', f"Network error: {type(e).__name__}"
    finally:
        # Crucial: always close the socket
        s.close()

def write_output_file(target, results, filename, elapsed_time):
    """Writes the scan results to a specified file."""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write(f"Web App Focused Scanner Results - Target: {target}\n")
            f.write(f"Scan Completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Time Elapsed: {elapsed_time:.2f} seconds\n")
            f.write("=" * 100 + "\n\n")

            f.write(f"{'Port':<6} | {'Status':<10} | {'Service/Banner/HTTP Status'}\n")
            f.write("-" * 100 + "\n")

            # Write open ports first
            open_ports = sorted([r for r in results if r[1] == 'open'], key=lambda x: x[0])
            for port, status, info in open_ports:
                f.write(f"{port:<6} | {status.upper():<10} | {info}\n")
            
            # Write filtered ports next
            filtered_ports = sorted([r for r in results if r[1] == 'filtered'], key=lambda x: x[0])
            for port, status, info in filtered_ports:
                f.write(f"{port:<6} | {status.upper():<10} | Firewall/Timeout\n")

            # Write closed ports last (optional, often noisy)
            closed_ports = sorted([r for r in results if r[1] == 'closed'], key=lambda x: x[0])
            for port, status, info in closed_ports:
                f.write(f"{port:<6} | {status.capitalize():<10} | {COMMON_PORTS.get(port, 'Unknown')}\n")

        print(f"\n[INFO] Detailed results saved to: {filename}")
    except Exception as e:
        print(f"\n[ERROR] Failed to write output file {filename}: {e}")

def run_nmap_scan(target, open_ports):
    """Executes a targeted Nmap scan using subprocess."""
    if not open_ports:
        print("\n[INFO] No open ports found to pass to Nmap.")
        return

    # Convert list of ports to Nmap format: '80,443,22'
    ports_str = ",".join(map(str, open_ports))
    
    # Construct the final command
    nmap_command = f"{NMAP_BASE_CMD} -p {ports_str} {target}"
    
    print("\n" + "=" * 100)
    print(f"[NMAP INTEGRATION] Running targeted Nmap scan (requires 'nmap' binary):")
    print(f"[NMAP COMMAND] {nmap_command}")
    print("=" * 100)

    try:
        # Execute the Nmap command and stream output
        process = subprocess.run(nmap_command, shell=True, check=True, text=True)
        # Nmap output is automatically displayed to the console
        
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Nmap execution failed. Check if 'nmap' is installed and in your PATH.")
        print(f"Details: {e}")
    except FileNotFoundError:
        print(f"[ERROR] Nmap binary not found. Please install Nmap to use the '--nmap-scan' feature.")


def main():
    """
    Main function to handle argument parsing and orchestrate the scan.
    """
    parser = argparse.ArgumentParser(
        description="A multithreaded TCP scanner with web-focused Service Version Detection (HTTP Status/Banner) and Nmap Integration.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
        Example 1 (Web app scan with Virtual Host): 
          python port_scanner.py 192.168.1.1 -p 80,443 -H app.vhost.com
        
        Example 2 (Fast-Track, custom agent, Nmap Integration, and Output): 
          python port_scanner.py target.net -F --nmap-scan -o scan.log
          
        NOTE: '--nmap-scan' requires the 'nmap' binary to be installed on your system.
        """
    )
    parser.add_argument("target", help="The target IP address or hostname to scan.")
    
    # Port Selection Group
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p", "--ports",
        help=f"Ports to scan (e.g., '80,443' or '1-1024'). Defaults to {DEFAULT_PORTS_ARG}.",
        default=DEFAULT_PORTS_ARG
    )
    group.add_argument(
        "-F", "--fast",
        action="store_true",
        help=f"Creative Option: Scan only the Top {len(TOP_PORTS)} most common ports for rapid reconnaissance.",
    )
    
    # Advanced Web App Specific Flags
    parser.add_argument(
        "-H", "--host-header",
        type=str,
        default="",
        help="Specify the Host header (hostname) for HTTP requests (crucial for virtual hosts). Defaults to TARGET IP.",
    )
    parser.add_argument(
        "--user-agent",
        type=str,
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
        help="Custom User-Agent string for HTTP checks.",
    )
    
    # Performance and Output
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help=f"Number of concurrent threads (workers). Max is {MAX_WORKERS}. Defaults to 100."
    )
    parser.add_argument(
        "-w", "--wait",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help=f"Connection timeout in seconds. Lower is faster but less reliable. Defaults to {DEFAULT_CONNECT_TIMEOUT}s.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="",
        help=f"Output file to save detailed results (e.g., scan.txt).",
    )
    
    # Nmap Integration Flag (NEW)
    parser.add_argument(
        "--nmap-scan",
        action="store_true",
        help="After the fast scan, execute a targeted Nmap Service/Script scan (-sV, -sC) on found open ports."
    )
    
    args = parser.parse_args()

    # 1. Input Validation and Setup
    if args.fast:
        ports_to_scan = TOP_PORTS
        port_display = f"Top {len(TOP_PORTS)} ports"
    else:
        ports_to_scan = parse_port_range(args.ports)
        port_display = args.ports
        
    if not ports_to_scan:
        return

    num_threads = min(args.threads, MAX_WORKERS)
    
    # Attempt to resolve the hostname/target
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[FATAL] Cannot resolve hostname: {args.target}")
        return

    # Use the argument host-header, or default to the target provided
    host_header = args.host_header if args.host_header else args.target

    # 2. Pre-Scan Summary
    print("=" * 100)
    print(f"Target: {args.target} ({target_ip})")
    print(f"Host Header (HTTP): {host_header}")
    print(f"User-Agent: {args.user_agent[:50]}...")
    print(f"Ports: {len(ports_to_scan)} ports ({port_display})")
    print(f"Threads: {num_threads} workers | Timeout: {args.wait}s")
    print(f"Scan Type: TCP Connect Scan with Web App Fingerprinting (HTTP HEAD)")
    if args.nmap_scan:
        print(f"POST-SCAN ACTION: Nmap Scripting Engine (NSE) Integration ENABLED.")
    print("=" * 100)
    print(f"{'PORT':<6} | {'STATUS':<10} | {'SERVICE/BANNER/HTTP STATUS'}")
    print("-" * 100)

    start_time = time.time()
    scan_results = []
    
    # 3. Execute Scan with Thread Pool
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port, args.wait, host_header, args.user_agent)
            for port in ports_to_scan
        ]

        # Process results as they complete
        for future in futures:
            port, status, info = future.result()
            scan_results.append((port, status, info))
            
            # Print 'open' or 'filtered' results immediately
            if status == 'open':
                print(f"{port:<6} | {status.upper():<10} | {info}")
            elif status == 'filtered':
                print(f"{port:<6} | {status.upper():<10} | Firewall/Timeout")

    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # 4. Final Summary
    open_ports = [r[0] for r in scan_results if r[1] == 'open'] # Extract just the port number
    filtered_ports = [r for r in scan_results if r[1] == 'filtered']
    
    print("-" * 100)
    print("SCAN SUMMARY")
    print("-" * 100)
    print(f"Total Ports Scanned: {len(ports_to_scan)}")
    print(f"Open Ports Found:    {len(open_ports)}")
    print(f"Filtered Ports:      {len(filtered_ports)}")
    print(f"Time Elapsed:        {elapsed_time:.2f} seconds")
    print("=" * 100)

    # 5. Output to File
    if args.output:
        write_output_file(args.target, scan_results, args.output, elapsed_time)
        
    # 6. Nmap Integration
    if args.nmap_scan:
        run_nmap_scan(args.target, open_ports)

if __name__ == "__main__":
    main()
