import argparse
import sys

from log_parser import FirewallLogParser
from reporter import FirewallReporter


def main():
    parser = argparse.ArgumentParser(
        description="Firewall Log Parser + Security Reporter"
    )

    parser.add_argument(
        "logfile",
        help="Path to the firewall log file"
    )

    args = parser.parse_args()

    try:
        log_parser = FirewallLogParser()
        events = log_parser.parse_file(args.logfile)

        if not events:
            print("[!] No valid firewall events found.")
            sys.exit(1)

        reporter = FirewallReporter(events)

        print(reporter.generate_report())

    except FileNotFoundError:
        print(f"[!] File not found: {args.logfile}")
        sys.exit(1)

    except PermissionError:
        print(f"[!] Permission denied: {args.logfile}")
        sys.exit(1)

    except Exception as error:
        print(f"[!] Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
