from collections import Counter
from typing import List

from log_parser import FirewallEvent


class FirewallReporter:
    """Generate statistics and reports from firewall events."""

    def __init__(self, events: List[FirewallEvent]):
        self.events = events

    def total_events(self) -> int:
        return len(self.events)

    def action_counts(self) -> Counter:
        return Counter(event.action for event in self.events)

    def top_source_ips(self, limit: int = 10) -> list[tuple[str, int]]:
        blocked_events = [
            event for event in self.events
            if event.action in ("BLOCK", "DENY")
        ]

        return Counter(
            event.src_ip for event in blocked_events
        ).most_common(limit)

    def top_destination_ports(self, limit: int = 10) -> list[tuple[int, int]]:
        return Counter(
            event.dst_port for event in self.events
        ).most_common(limit)

    def top_rules(self, limit: int = 10) -> list[tuple[str, int]]:
        return Counter(
            event.rule for event in self.events
        ).most_common(limit)

    def protocol_counts(self) -> Counter:
        return Counter(
            event.protocol for event in self.events
        )

    def generate_report(self) -> str:
        actions = self.action_counts()
        protocols = self.protocol_counts()

        lines = []

        lines.append("=" * 60)
        lines.append("           FIREWALL SECURITY REPORT")
        lines.append("=" * 60)

        lines.append("")
        lines.append("GENERAL STATISTICS")
        lines.append("-" * 60)

        lines.append(f"Total events : {self.total_events()}")
        lines.append(f"Allowed      : {actions.get('ALLOW', 0)}")
        lines.append(f"Blocked      : {actions.get('BLOCK', 0)}")
        lines.append(f"Denied       : {actions.get('DENY', 0)}")

        lines.append("")
        lines.append("PROTOCOLS")
        lines.append("-" * 60)

        for protocol, count in protocols.most_common():
            lines.append(f"{protocol:<10} {count}")

        lines.append("")
        lines.append("TOP BLOCKED SOURCE IPs")
        lines.append("-" * 60)

        for ip, count in self.top_source_ips():
            lines.append(f"{ip:<20} {count} blocks")

        lines.append("")
        lines.append("TOP DESTINATION PORTS")
        lines.append("-" * 60)

        for port, count in self.top_destination_ports():
            lines.append(f"{port:<10} {count} events")

        lines.append("")
        lines.append("TOP FIREWALL RULES")
        lines.append("-" * 60)

        for rule, count in self.top_rules():
            lines.append(f"{rule:<25} {count} hits")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)
