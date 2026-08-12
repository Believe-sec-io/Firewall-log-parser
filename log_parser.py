import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class FirewallEvent:
    timestamp: str
    action: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    rule: str


class FirewallLogParser:
    """
    Parser for firewall logs.

    Expected log format:

    2026-08-12 20:15:32 ACTION=BLOCK SRC=192.168.1.10 DST=10.0.0.5 SRC_PORT=54321 DST_PORT=22 PROTO=TCP RULE=SSH_BLOCK
    """

    LOG_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
        r"ACTION=(?P<action>\w+)\s+"
        r"SRC=(?P<src_ip>\S+)\s+"
        r"DST=(?P<dst_ip>\S+)\s+"
        r"SRC_PORT=(?P<src_port>\d+)\s+"
        r"DST_PORT=(?P<dst_port>\d+)\s+"
        r"PROTO=(?P<protocol>\w+)\s+"
        r"RULE=(?P<rule>\S+)"
    )

    def parse_line(self, line: str) -> Optional[FirewallEvent]:
        """
        Parse one firewall log line.

        Returns:
            FirewallEvent if the line is valid.
            None if the line cannot be parsed.
        """

        line = line.strip()

        if not line:
            return None

        match = self.LOG_PATTERN.match(line)

        if not match:
            return None

        data = match.groupdict()

        return FirewallEvent(
            timestamp=data["timestamp"],
            action=data["action"].upper(),
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=int(data["src_port"]),
            dst_port=int(data["dst_port"]),
            protocol=data["protocol"].upper(),
            rule=data["rule"],
        )

    def parse_file(self, filepath: str) -> list[FirewallEvent]:
        """
        Parse a complete firewall log file.
        """

        events = []

        with open(filepath, "r", encoding="utf-8") as file:
            for line in file:
                event = self.parse_line(line)

                if event:
                    events.append(event)

        return events
