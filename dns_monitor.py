from __future__ import annotations
import dns.resolver
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


TRUSTED_DNS = "1.1.1.1"
DEFAULT_INTERVAL = 10


@dataclass
class DNSRecord:
    timestamp: float
    domain: str
    system_ips: List[str]
    trusted_ips: List[str]
    message: str


class DNSMonitor:
    def __init__(self, domain_list: List[str], interval: int = DEFAULT_INTERVAL):
        self.domain_list = domain_list
        self.interval = interval

        self.baseline: Dict[str, List[str]] = {}

        self.events: List[DNSRecord] = []

    def _resolve_system(self, domain: str) -> List[str]:
        try:
            res = dns.resolver.resolve(domain, "A")
            return sorted([rdata.address for rdata in res])
        except Exception:
            return []

    def _resolve_trusted(self, domain: str) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [TRUSTED_DNS]
            res = resolver.resolve(domain, "A")
            return sorted([rdata.address for rdata in res])
        except Exception:
            return []

    def _log(self, domain, sys_ips, trusted_ips, message):
        ts = time.time()
        record = DNSRecord(ts, domain, sys_ips, trusted_ips, message)
        self.events.append(record)

        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        print(f"[{t_str}] [DNS] {message}")
        print(f"    Domain      : {domain}")
        print(f"    System DNS  : {sys_ips}")
        print(f"    Trusted DNS : {trusted_ips}")
        print("-" * 50)

    def build_baseline(self):
        print("[+] Building DNS baseline...")
        for domain in self.domain_list:
            ips = self._resolve_system(domain)
            self.baseline[domain] = ips
            self._log(domain, ips, ips, "Baseline DNS resolved.")

    def start(self):
        self.build_baseline()
        print("[+] Starting DNS integrity monitoring...\n")

        while True:
            for domain in self.domain_list:
                sys_ips = self._resolve_system(domain)
                trusted_ips = self._resolve_trusted(domain)

                if sys_ips != self.baseline[domain]:
                    self._log(
                        domain,
                        sys_ips,
                        trusted_ips,
                        "⚠️ System resolver IP changed from baseline!"
                    )

                if sys_ips != trusted_ips:
                    self._log(
                        domain,
                        sys_ips,
                        trusted_ips,
                        "⚠️ System DNS does not match trusted resolver!"
                    )

            time.sleep(self.interval)


def main():
    print("=== DNS Integrity Monitor ===")
    print("Enter domains to monitor (one per line). Blank to finish:\n")

    domains = []
    while True:
        line = input("> ").strip()
        if not line:
            break
        domains.append(line)

    if not domains:
        print("[!] No domains entered. Exiting.")
        return

    interval = input("Check interval (seconds, default 10): ").strip()
    try:
        interval = int(interval)
    except:
        interval = DEFAULT_INTERVAL

    monitor = DNSMonitor(domains, interval=interval)
    monitor.start()


if __name__ == "__main__":
    main()
