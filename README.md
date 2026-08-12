## Features Log Parser + Reporter

A Python-based security tool for parsing firewall logs, analyzing firewall activity, and generating readable security reports.

«Project status: Prototype / early development
Production-ready features will be added progressively.»

# Features

- Parse structured firewall logs
- Extract source and destination IP addresses
- Extract source and destination ports
- Identify network protocols
- Identify firewall actions:
  - "ALLOW"
  - "BLOCK"
  - "DENY"
- Track firewall rules
- Generate security statistics
- Identify frequently blocked source IPs
- Identify frequently targeted ports
- Identify frequently triggered firewall rules
- Display a readable terminal report

Project Structure

firewall-log-parser/
│
├── main.py
├── log_parser.py
├── reporter.py
├── sample_firewall.log
├── requirements.txt
└── README.md

Requirements

- Python 3.9 or newer
- No external dependencies are currently required.

Installation

Clone the repository:

git clone https://github.com/yourusername/firewall-log-parser.git
cd firewall-log-parser

Run the project:

python main.py sample_firewall.log

Log Format

The current parser expects logs in the following format:

2026-08-12 20:15:32 ACTION=BLOCK SRC=192.168.1.10 DST=10.0.0.5 SRC_PORT=54321 DST_PORT=22 PROTO=TCP RULE=SSH_BLOCK

Example:

2026-08-12 20:15:32 ACTION=BLOCK SRC=192.168.1.10 DST=10.0.0.5 SRC_PORT=54321 DST_PORT=22 PROTO=TCP RULE=SSH_BLOCK
2026-08-12 20:16:04 ACTION=ALLOW SRC=192.168.1.20 DST=10.0.0.5 SRC_PORT=49152 DST_PORT=443 PROTO=TCP RULE=HTTPS_ALLOW
2026-08-12 20:17:12 ACTION=BLOCK SRC=192.168.1.15 DST=10.0.0.5 SRC_PORT=44444 DST_PORT=3389 PROTO=TCP RULE=RDP_BLOCK

Usage

Basic usage:

python main.py sample_firewall.log

The tool parses the log and generates a report containing:

GENERAL STATISTICS
------------------
Total events
Allowed events
Blocked events
Denied events

PROTOCOLS
---------
TCP
UDP
...

TOP BLOCKED SOURCE IPs
----------------------
Source IP
Number of blocks

TOP DESTINATION PORTS
---------------------
Port
Number of events

TOP FIREWALL RULES
------------------
Rule
Number of hits

Example Output

============================================================
           FIREWALL SECURITY REPORT
============================================================

GENERAL STATISTICS
------------------------------------------------------------
Total events : 3
Allowed      : 1
Blocked      : 2
Denied       : 0

PROTOCOLS
------------------------------------------------------------
TCP        3

TOP BLOCKED SOURCE IPs
------------------------------------------------------------
192.168.1.10        1 blocks
192.168.1.15        1 blocks

TOP DESTINATION PORTS
------------------------------------------------------------
22         1 events
443        1 events
3389       1 events

TOP FIREWALL RULES
------------------------------------------------------------
SSH_BLOCK                 1 hits
HTTPS_ALLOW               1 hits
RDP_BLOCK                 1 hits

============================================================

Security Use Cases

This project can be useful for:

- SOC analyst training
- Firewall log analysis
- Incident investigation
- Network security monitoring
- Identifying repeated blocked connections
- Identifying targeted services
- Understanding firewall rule activity
- Security reporting

Roadmap

Future versions will add:

- [ ] Robust log validation
- [ ] IPv4 and IPv6 validation
- [ ] Multiple firewall log formats
- [ ] Windows Firewall log support
- [ ] iptables log support
- [ ] pfSense log support
- [ ] Cisco ASA log support
- [ ] Suspicious IP detection
- [ ] Port scanning detection
- [ ] Burst/event-rate detection
- [ ] Configurable detection thresholds
- [ ] JSON export
- [ ] CSV export
- [ ] Automated reports
- [ ] Colored terminal interface
- [ ] Unit tests
- [ ] Configuration file
- [ ] Production-ready error handling

Disclaimer

This project is intended for defensive security, monitoring, learning, and authorized environments.

Only analyze firewall logs that you own or have explicit permission to analyze.

License

MIT License
