from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Dict, Optional
from scapy.all import sniff, ARP, conf

@dataclass
class _event:
    timestamp: float
    ip: str
    old_mac: Optional[str]
    new_mac: str
    message: str

class ARPMonitor:
    def __init__(self, iface: Optional[str]=None):
        self.iface = iface
        self.ip_to_mac: Dict[str, str] = {}
        self.events: list[_event] = []

    def _log(self, ip: str, old_mac: Optional[str], new_mac: str, msg: str):
        ts = time.time()
        event = _event(
            timestamp=ts,
            ip=ip,
            old_mac=old_mac,
            new_mac=new_mac,
            message=msg,
        )
        self.events.append(event)

        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        print(f"[{t_str}] [ARP] {msg}")
        print(f"    IP      : {ip}")
        print(f"    New MAC : {new_mac}")
        if old_mac:
            print(f"    Old MAC : {old_mac}")

    def handle(self, pkt):
        if not pkt.haslayer(ARP):
            return
        
        arp = pkt[ARP]

        if arp.op not in (2,1):
            return
        
        ip = arp.psrc
        mac = arp.hwsrc

        if not ip or not mac:
            return
        
        if ip not in self.ip_to_mac:
            self.ip_to_mac[ip] = mac
            self._log(
                ip,
                old_mac=None,
                new_mac=mac,
                msg=f"New ARP : {ip} at {mac}",
            )
            return
        
        if self.ip_to_mac[ip] == mac:
            return

        old_mac = self.ip_to_mac[ip]
        self.ip_to_mac[ip] = mac

        self._log(
            ip,
            old_mac=old_mac,
            new_mac=mac,
            msg="Possible ARP spoofing",
        )

    def start(self, count: int = 0):
        print("=== ARP Monitor ===")
        if self.iface:
            print(f"Listening on interface: {self.iface}")
        else:
            print("Listening on Scapy default interface")

        print("Press Ctrl+C to stop.\n")

        try:
            sniff(
                iface=self.iface,
                filter="arp",
                prn=self.handle,
                store=False,
                count=count
            )
        except PermissionError:
            print("Permission denied. Try running as root/with sudo.")
        except KeyboardInterrupt:
            print("\nStopped by user.")
        except Exception as e:
            print(f"Error during sniffing: {e}")

def main():
    if sniff is None:
        print("Scapy is not installed. Install it with:")
        return
    print("=== ARP Spoofing Detector ===")
    print("Leave interface blank to use Scapy default.\n")
    iface = input("Interface (e.g. eth0, wlan0): ").strip() or None
    monitor = ARPMonitor(iface=iface)
    monitor.start(count=0)


if __name__ == "__main__":
    main()
