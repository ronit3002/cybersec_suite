# Cybersecurity Suite

A small collection of Python cybersecurity tools built for learning defensive security, networking, and monitoring concepts.

The suite currently includes:

```text
cybersec_suite/
├── arp_monitor.py
├── dns_monitor.py
├── scanner.py
└── README.md
```

## Tools Included

### 1. ARP Monitor

`arp_monitor.py` monitors ARP traffic on the local network and watches for changes in IP-to-MAC address mappings.

It can help detect suspicious behavior such as possible ARP spoofing, where an IP address suddenly appears to be associated with a different MAC address.

Features:

- Sniffs ARP packets using Scapy
- Tracks IP-to-MAC mappings
- Logs new ARP entries
- Detects when an IP address changes MAC address
- Prints timestamped alerts
- Supports a custom network interface

Example output:

```text
[2026-05-17 11:20:00] [ARP] Possible ARP spoofing
    IP      : 192.168.1.1
    New MAC : aa:bb:cc:dd:ee:ff
    Old MAC : 11:22:33:44:55:66
```

---

### 2. DNS Monitor

`dns_monitor.py` monitors DNS integrity for a list of domains.

It compares the system DNS resolver against a trusted resolver and also watches for changes from the original baseline.

Features:

- Accepts multiple domains from user input
- Builds an initial DNS baseline
- Periodically checks DNS records
- Compares system DNS results with Cloudflare DNS `1.1.1.1`
- Logs DNS changes and mismatches
- Useful for learning about DNS poisoning and resolver integrity

Example output:

```text
[2026-05-17 11:25:00] [DNS] System DNS does not match trusted resolver!
    Domain      : example.com
    System DNS  : ['93.184.216.34']
    Trusted DNS : ['93.184.216.35']
--------------------------------------------------
```

---

### 3. Port Scanner

`scanner.py` is an asynchronous TCP port scanner.

It scans a target host over a selected port range and reports open ports, likely services, and a simple severity rating.

Features:

- Scans hostnames or IP addresses
- Supports custom port ranges
- Uses `asyncio` for faster scanning
- Maps common ports to service names
- Adds simple severity ratings
- Reports scan duration

Example output:

```text
Scanning scanme.example.com (192.0.2.10) on ports 1-1024...

Scan completed in 2.45s
----------------------------------------
Port 22    OPEN   | SSH        | Severity: MEDIUM
Port 80    OPEN   | HTTP       | Severity: LOW
Port 443   OPEN   | HTTPS      | Severity: LOW
----------------------------------------
```

## Tech Stack

- Python
- Scapy
- dnspython
- asyncio
- socket
- argparse
- dataclasses

## Installation

Clone the repository:

```bash
git clone https://github.com/ronit3002/cybersec_suite.git
cd cybersec_suite
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Run the ARP Monitor

```bash
sudo python arp_monitor.py
```

The ARP monitor may require administrator/root privileges because packet sniffing usually needs elevated permissions.

You can enter a network interface when prompted, such as:

```text
eth0
wlan0
```

Or leave it blank to use Scapy's default interface.

### Run the DNS Monitor

```bash
python dns_monitor.py
```

Then enter domains one by one:

```text
google.com
github.com
example.com
```

Press Enter on a blank line to start monitoring.

### Run the Port Scanner

Scan the default range, `1-1024`:

```bash
python scanner.py example.com
```

Scan a custom range:

```bash
python scanner.py example.com --range 1-5000
```

Scan a local machine:

```bash
python scanner.py 127.0.0.1 --range 1-1024
```


## Limitations

- The ARP monitor only detects suspicious IP-to-MAC changes; it does not prove an attack by itself.
- The DNS monitor compares A records only.
- DNS results may differ naturally because of CDNs, load balancing, and location-based DNS.
- The port scanner only checks whether TCP ports are open.
- Service detection is based on common port numbers, not banner grabbing.
- The severity rating is basic and should not be treated as a full vulnerability assessment.

## Future Improvements

- Add a unified menu to launch all tools
- Add logging to files
- Export results as JSON or CSV
- Add banner grabbing to the port scanner
- Add UDP scanning support
- Add IPv6 support
- Add DNS record type selection
- Add email or desktop alerts
- Add configuration files
- Add a simple dashboard

## Ethical Use

This project is for educational and defensive cybersecurity learning only.
