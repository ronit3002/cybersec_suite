import asyncio
import socket
import time
import sys
import argparse

SERVICE_MAP = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt"
}

def severity_for_port(port: int) -> str:
    if port in (3306, 5432, 6379):
        return "HIGH"
    if port == 22:
        return "MEDIUM"
    return "LOW"

def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        print(f"Could not resolve host: {e}")
        sys.exit(1)

def _sync_check(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False

async def scan_port(ip: str, port: int, timeout=1.0):
    loop = asyncio.get_event_loop()
    try:
        fut = loop.run_in_executor(None, _sync_check, ip, port, timeout)
        return port, await asyncio.wait_for(fut, timeout + 0.2)
    except Exception:
        return port, False

async def scan_ports(ip: str, ports):
    semaphore = asyncio.Semaphore(500)
    results = []

    async def worker(p):
        async with semaphore:
            port, is_open = await scan_port(ip, p)
            results.append((port, is_open))

    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(results)

def parse_port_range(port_range: str):
    if "-" not in port_range:
        print("Invalid range format. Use: 1-1024")
        sys.exit(1)
    start, end = port_range.split("-")
    return range(int(start), int(end) + 1)

async def main():
    parser = argparse.ArgumentParser(description="Python Port Scanner")
    parser.add_argument("target", help="Hostname or IP to scan")
    parser.add_argument(
        "--range", default="1-1024",
        help="Range of ports to scan, e.g. 1-1024"
    )
    args = parser.parse_args()

    target = args.target
    ports = parse_port_range(args.range)
    ip = resolve_host(target)

    print(f"Scanning {target} ({ip}) on ports {args.range}...")
    start = time.time()

    results = await scan_ports(ip, ports)
    duration = time.time() - start

    print(f"\nScan completed in {duration:.2f}s")
    print("-" * 40)

    any_open = False

    for port, is_open in results:
        if is_open:
            any_open = True
            service = SERVICE_MAP.get(port, "Unknown")
            sev = severity_for_port(port)
            print(f"Port {port:<5} OPEN   | {service:<10} | Severity: {sev}")

    if not any_open:
        print("No open ports found in this range.")

    print("-" * 40)

if __name__ == "__main__":
    asyncio.run(main())
