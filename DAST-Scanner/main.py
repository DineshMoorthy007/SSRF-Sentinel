from core.scanner import Scanner

def main():

    scanner = Scanner()

    try:
        scanner.display_banner()
        if not scanner.check_target():
            print("\n[ERROR] Scanner initialization failed.")
            return

        print("\n[SUCCESS] Scanner initialized successfully.")

        # Phase 3: Endpoint discovery
        scanner.discover_endpoints()

        # Phase 4: Parameter analysis
        scanner.analyze_parameters()

        # Phase 5: SSRF detection
        scanner.detect_ssrf()

        # Phase 8: JSON report generation
        scanner.generate_reports()

        print("\n[SUCCESS] DAST scanning completed.")

    finally:
        scanner.close()

if __name__ == "__main__":
    main()