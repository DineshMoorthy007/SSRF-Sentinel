import sys
import argparse
from core.scanner import Scanner


def run_scan(mode: str = "vulnerable"):
    scanner = Scanner(mode=mode)
    try:
        scanner.display_banner()
        if not scanner.check_target():
            print("\n[ABORTED] Integration scanning stopped because target is unavailable.")
            return False

        print("\n[SUCCESS] Scanner initialized against actual C++ target application.")

        # Phase 3: Endpoint discovery
        scanner.discover_endpoints()

        # Phase 4: Parameter analysis
        scanner.analyze_parameters()

        # Phase 5: SSRF detection
        scanner.detect_ssrf()

        # Phase 8: JSON report generation
        filename = f"ssrf_report_{mode}.json" if mode != "vulnerable" else "ssrf_report.json"
        scanner.generate_reports(filename=filename)

        print(f"\n[SUCCESS] SSRF Sentinel scan completed successfully in {mode.upper()} mode.")
        return True

    finally:
        scanner.close()


def main():
    parser = argparse.ArgumentParser(
        description="SSRF Sentinel - Advanced Multi-Engine SSRF DAST Scanner"
    )
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure", "both"],
        default="vulnerable",
        help="Scanning evaluation mode: 'vulnerable' (default), 'secure', or 'both'"
    )
    args = parser.parse_args()

    if args.mode == "both":
        print("\n>>> EXECUTING SCAN 1/2: VULNERABLE MODE <<<")
        success_vuln = run_scan(mode="vulnerable")
        if not success_vuln:
            sys.exit(1)

        print("\n" + "#" * 65)
        print(">>> EXECUTING SCAN 2/2: SECURE MODE (DEFENSIVE VALIDATION) <<<")
        print("#" * 65)
        success_sec = run_scan(mode="secure")
        if not success_sec:
            sys.exit(1)
    else:
        success = run_scan(mode=args.mode)
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    main()
