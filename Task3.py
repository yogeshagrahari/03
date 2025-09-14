# #!/usr/bin/env python3
# """
# 🌐 BASIC NETWORK PORT SCANNER - Task 3
# Advanced Python Port Scanner with Multi-threading and Rate Limiting

# Author: Cybersecurity Student  
# Date: September 2025
# Description: A comprehensive TCP port scanner for authorized penetration testing

# Features:
# - Multi-threaded scanning for speed
# - Rate limiting to avoid overwhelming targets
# - Comprehensive error handling
# - Service identification
# - Multiple scan modes (normal, stealth, quick)
# - Professional reporting with security recommendations
# """

import socket
import sys
import threading
import time
from datetime import datetime

class NetworkPortScanner:
    def __init__(self, target_host, start_port=1, end_port=1000, timeout=1, max_threads=100):
        """
        Initialize the port scanner

        Args:
            target_host (str): Target IP address or hostname
            start_port (int): Starting port number
            end_port (int): Ending port number
            timeout (int): Connection timeout in seconds
            max_threads (int): Maximum number of concurrent threads
        """
        self.target_host = target_host
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.lock = threading.Lock()
        self.scan_start_time = None

    def validate_host(self):
        """
        Validate if the target host is reachable

        Returns:
            bool: True if host is reachable, False otherwise
        """
        try:
            # Try to resolve the hostname to IP
            target_ip = socket.gethostbyname(self.target_host)
            print(f"[INFO] Target resolved: {self.target_host} -> {target_ip}")

            # Warn about scanning restrictions for non-local targets
            if not self._is_local_target(target_ip):
                print(f"[WARNING] Scanning {target_ip}. Ensure you have authorization.")
                print("[INFO] Only scan systems you own or have permission to test.")

            return True

        except socket.gaierror:
            print(f"[ERROR] Could not resolve hostname: {self.target_host}")
            return False
        except Exception as e:
            print(f"[ERROR] Host validation failed: {e}")
            return False

    def _is_local_target(self, ip):
        """
        Check if target is localhost or local network

        Args:
            ip (str): IP address to check

        Returns:
            bool: True if local target
        """
        local_ips = ['127.0.0.1', '::1', 'localhost']
        return ip in local_ips or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')

    def scan_single_port(self, port):
        """
        Scan a single port on the target host

        Args:
            port (int): Port number to scan
        """
        try:
            # Create socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Attempt to connect
            result = sock.connect_ex((self.target_host, port))

            with self.lock:
                if result == 0:
                    # Port is open
                    self.open_ports.append(port)
                    try:
                        # Try to get service name
                        service = socket.getservbyport(port)
                        print(f"[OPEN] Port {port}/tcp - {service}")
                    except:
                        print(f"[OPEN] Port {port}/tcp - Unknown service")
                else:
                    # Port is closed
                    self.closed_ports.append(port)

            sock.close()

        except socket.timeout:
            # Port is filtered (firewall/timeout)
            with self.lock:
                self.filtered_ports.append(port)

        except socket.error as e:
            # Connection refused or other error
            with self.lock:
                if "Connection refused" in str(e):
                    self.closed_ports.append(port)
                else:
                    self.filtered_ports.append(port)
        except Exception as e:
            # Unexpected error
            with self.lock:
                self.filtered_ports.append(port)

    def scan_ports(self):
        """
        Main port scanning function using multithreading

        Returns:
            bool: True if scan completed successfully
        """
        print(f"\n[INFO] Starting port scan on {self.target_host}")
        print(f"[INFO] Port range: {self.start_port}-{self.end_port}")
        print(f"[INFO] Timeout: {self.timeout}s")
        print(f"[INFO] Max threads: {self.max_threads}")
        print(f"[INFO] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)

        # Validate host before scanning
        if not self.validate_host():
            print("[ERROR] Host validation failed. Aborting scan.")
            return False

        self.scan_start_time = time.time()
        threads = []

        try:
            # Create and start threads for port scanning
            for port in range(self.start_port, self.end_port + 1):
                # Rate limiting: limit concurrent threads
                while len([t for t in threads if t.is_alive()]) >= self.max_threads:
                    time.sleep(0.01)  # Small delay to prevent overwhelming

                thread = threading.Thread(target=self.scan_single_port, args=(port,))
                thread.daemon = True  # Daemon thread for clean exit
                thread.start()
                threads.append(thread)

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            return True

        except KeyboardInterrupt:
            print("\n[INFO] Scan interrupted by user. Generating partial results...")
            return True
        except Exception as e:
            print(f"[ERROR] Scan failed: {e}")
            return False

    def get_port_service(self, port):
        """
        Get service name for a port number

        Args:
            port (int): Port number

        Returns:
            str: Service name or 'Unknown'
        """
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"

    def get_scan_duration(self):
        """
        Calculate scan duration

        Returns:
            str: Formatted scan duration
        """
        if self.scan_start_time:
            duration = time.time() - self.scan_start_time
            return f"{duration:.2f} seconds"
        return "Unknown"

    def report_results(self):
        """
        Generate and display comprehensive scan results
        """
        print("\n" + "=" * 60)
        print("PORT SCAN RESULTS")
        print("=" * 60)

        print(f"Target Host: {self.target_host}")
        print(f"Scan Range: {self.start_port}-{self.end_port}")
        print(f"Scan Duration: {self.get_scan_duration()}")
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)

        # Open ports with detailed information
        if self.open_ports:
            print(f"\n[OPEN PORTS] ({len(self.open_ports)} found)")
            print("-" * 30)
            print("Port\tService\t\tDescription")
            print("-" * 30)

            for port in sorted(self.open_ports):
                service = self.get_port_service(port)
                description = self._get_port_description(port)
                print(f"{port}/tcp\t{service:<12}\t{description}")
        else:
            print("\n[OPEN PORTS] None found")

        # Filtered ports summary (if significant)
        if len(self.filtered_ports) > 0:
            print(f"\n[FILTERED PORTS] {len(self.filtered_ports)} ports appear filtered")

        # Summary statistics
        print(f"\n[SUMMARY]")
        print("-" * 30)
        total_ports = self.end_port - self.start_port + 1
        print(f"Total ports scanned: {total_ports}")
        print(f"Open ports: {len(self.open_ports)}")
        print(f"Closed ports: {len(self.closed_ports)}")
        print(f"Filtered ports: {len(self.filtered_ports)}")

        if total_ports > 0:
            open_percentage = (len(self.open_ports) / total_ports) * 100
            print(f"Open port ratio: {open_percentage:.1f}%")

        # Security recommendations
        if self.open_ports:
            self._print_security_recommendations()

    def _get_port_description(self, port):
        """
        Get detailed description for common ports

        Args:
            port (int): Port number

        Returns:
            str: Port description
        """
        descriptions = {
            21: "FTP - File Transfer Protocol",
            22: "SSH - Secure Shell",
            23: "Telnet - Unencrypted text communication",
            25: "SMTP - Simple Mail Transfer Protocol",
            53: "DNS - Domain Name System",
            80: "HTTP - Hypertext Transfer Protocol",
            110: "POP3 - Post Office Protocol v3",
            143: "IMAP - Internet Message Access Protocol",
            443: "HTTPS - HTTP over TLS/SSL",
            993: "IMAPS - IMAP over TLS/SSL",
            995: "POP3S - POP3 over TLS/SSL",
            1723: "PPTP - Point-to-Point Tunneling Protocol",
            3306: "MySQL - Database Server",
            3389: "RDP - Remote Desktop Protocol",
            5900: "VNC - Virtual Network Computing",
            8080: "HTTP Alternate - Web Server"
        }
        return descriptions.get(port, "Unknown service")

    def _print_security_recommendations(self):
        """
        Print security recommendations based on open ports
        """
        print(f"\n[SECURITY RECOMMENDATIONS]")
        print("-" * 30)

        high_risk_ports = [21, 23, 135, 139, 445, 1433, 1521]
        medium_risk_ports = [22, 80, 443, 3389, 5900]

        high_risk_found = [p for p in self.open_ports if p in high_risk_ports]
        medium_risk_found = [p for p in self.open_ports if p in medium_risk_ports]

        if high_risk_found:
            print(f"🔴 HIGH RISK: Ports {high_risk_found} may pose security risks")
            print("   • Consider disabling unnecessary services")
            print("   • Implement strong access controls")
            print("   • Use VPN or firewall restrictions")

        if medium_risk_found:
            print(f"🟡 MEDIUM RISK: Ports {medium_risk_found} require monitoring")
            print("   • Ensure services are updated and patched")
            print("   • Use strong authentication")

        print("\n📋 GENERAL RECOMMENDATIONS:")
        print("• Review all open ports and ensure only necessary services are running")
        print("• Implement firewall rules to restrict access by IP/network")
        print("• Regularly monitor for unauthorized services")
        print("• Keep all services updated with latest security patches")
        print("• Use intrusion detection systems (IDS) for monitoring")
        print("• Conduct regular security assessments")

# Utility functions for different scan types
def quick_scan_common_ports(target, timeout=2):
    """
    Quick scan of most commonly used ports

    Args:
        target (str): Target IP or hostname
        timeout (int): Connection timeout
    """
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                   443, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

    print(f"\n🚀 QUICK SCAN - Common Ports on {target}")
    print("-" * 50)

    scanner = NetworkPortScanner(target, timeout=timeout, max_threads=20)

    for port in common_ports:
        scanner.scan_single_port(port)
        time.sleep(0.05)  # Rate limiting

    scanner.report_results()

def stealth_scan(target, start_port, end_port, delay=0.5):
    """
    Slower, more stealthy scan with longer delays

    Args:
        target (str): Target IP or hostname  
        start_port (int): Starting port
        end_port (int): Ending port
        delay (float): Delay between scans
    """
    print(f"\n🥷 STEALTH SCAN - {target}:{start_port}-{end_port}")
    print("Note: This scan will be slower to avoid detection")
    print("-" * 50)

    scanner = NetworkPortScanner(
        target_host=target,
        start_port=start_port,
        end_port=end_port,
        timeout=5,
        max_threads=5  # Lower thread count for stealth
    )

    if scanner.scan_ports():
        scanner.report_results()

def demo_scan():
    """
    Demo function to show basic usage
    """
    print("\n📚 DEMO: Basic localhost scan")
    print("-" * 40)

    # Demo scan of localhost ports 20-30
    scanner = NetworkPortScanner("127.0.0.1", 20, 30, timeout=1)
    if scanner.scan_ports():
        scanner.report_results()

def main():
    """
    Main function with interactive mode
    """
    print("🌐 BASIC NETWORK PORT SCANNER - Task 3")
    print("=" * 50)
    print("⚠️  IMPORTANT: Only scan systems you own or have explicit permission to test")
    print("=" * 50)

    while True:
        try:
            print("\nSCAN OPTIONS:")
            print("1. Quick scan (common ports)")
            print("2. Custom range scan")
            print("3. Stealth scan")
            print("4. Demo scan (localhost ports 20-30)")
            print("5. Exit")

            choice = input("\nSelect option (1-5): ").strip()

            if choice == "1":
                target = input("Enter target IP/hostname (default: 127.0.0.1): ").strip() or "127.0.0.1"
                quick_scan_common_ports(target)

            elif choice == "2":
                target = input("Enter target IP/hostname (default: 127.0.0.1): ").strip() or "127.0.0.1"
                start_port = int(input("Start port (default: 1): ") or "1")
                end_port = int(input("End port (default: 100): ") or "100")
                timeout = int(input("Timeout seconds (default: 1): ") or "1")

                scanner = NetworkPortScanner(target, start_port, end_port, timeout)
                if scanner.scan_ports():
                    scanner.report_results()

            elif choice == "3":
                target = input("Enter target IP/hostname (default: 127.0.0.1): ").strip() or "127.0.0.1"
                start_port = int(input("Start port (default: 1): ") or "1")
                end_port = int(input("End port (default: 50): ") or "50")
                stealth_scan(target, start_port, end_port)

            elif choice == "4":
                demo_scan()

            elif choice == "5":
                print("\n[INFO] Exiting port scanner. Stay secure!")
                break

            else:
                print("[ERROR] Invalid choice. Please select 1-5.")

        except KeyboardInterrupt:
            print("\n[INFO] Program interrupted by user")
            break
        except ValueError:
            print("[ERROR] Invalid input. Please enter numeric values.")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        sys.exit(1)
