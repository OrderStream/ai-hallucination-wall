"""
Command line interface for ai-hallucination-wall.
"""

import argparse
import sys
from pathlib import Path
from ai_hallucination_wall.core import AIHallucinationWall
from ai_hallucination_wall.monetization import LicenseManager

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ai-hallucination-wall",
        description="Security guardrail inspecting autonomous AI coding agent tool invocations, blocking hallucinated or typosquatted npm/PyPI dependencies"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # check-command
    cmd_parser = subparsers.add_parser("check-command", help="Inspect shell command before execution")
    cmd_parser.add_argument("--cmd", required=True, help="Command string to inspect (e.g. 'npm install expres')")
    cmd_parser.add_argument("--license-key", default=None, help="OrderStream license key")

    # scan-manifest
    manifest_parser = subparsers.add_parser("scan-manifest", help="Scan package.json or requirements.txt for hallucinated dependencies")
    manifest_parser.add_argument("--file", required=True, help="Path to manifest file")
    manifest_parser.add_argument("--license-key", default=None, help="OrderStream license key")

    # check-package
    pkg_parser = subparsers.add_parser("check-package", help="Inspect a specific package name")
    pkg_parser.add_argument("--name", required=True, help="Package name")
    pkg_parser.add_argument("--ecosystem", default="auto", choices=["auto", "pypi", "npm"], help="Package ecosystem")

    # license / donate command
    subparsers.add_parser("license", help="View license tier and 0% fee crypto donation wallets")

    args = parser.parse_args(argv)

    if not args.command or args.command == "license":
        print(LicenseManager.get_banner("ai-hallucination-wall"))
        tier = LicenseManager.get_tier(getattr(args, "license_key", None))
        print(f"Active Tier: {tier['name']} ({tier['tier']})")
        print(f"Features: {', '.join(tier['features'])}")
        print(LicenseManager.get_remediation_footer())
        return 0

    if args.command == "check-command":
        print(LicenseManager.get_banner("ai-hallucination-wall"))
        threats = AIHallucinationWall.inspect_command(args.cmd)
        if threats:
            print(f"🚨 [AI-HALLUCINATION-WALL] BLOCKED {len(threats)} malicious / hallucinated package(s)!")
            for t in threats:
                print(f"\n  [{t.severity}] Threat: {t.threat_type} in {t.ecosystem}")
                print(f"     Target: {t.package_name} (Similar to vetted: {t.matched_target})")
                print(f"     Reason: {t.message}")
                print(f"     👉 Fix: {t.remediation}")
            print(LicenseManager.get_remediation_footer())
            return 1
        
        print(f"✅ [AI-HALLUCINATION-WALL] PASSED: Command is clean and safe to execute.")
        return 0

    elif args.command == "scan-manifest":
        print(LicenseManager.get_banner("ai-hallucination-wall"))
        threats = AIHallucinationWall.scan_manifest(args.file)
        if threats:
            print(f"🚨 [AI-HALLUCINATION-WALL] Found {len(threats)} suspicious package(s) in {args.file}!")
            for t in threats:
                print(f"  [{t.severity}] {t.package_name}: {t.message}")
            print(LicenseManager.get_remediation_footer())
            return 1

        print(f"✅ [AI-HALLUCINATION-WALL] PASSED: No hallucinated dependencies in {args.file}.")
        return 0

    elif args.command == "check-package":
        rep = AIHallucinationWall.check_package(args.name, args.ecosystem)
        if rep:
            print(f"🚨 [AI-HALLUCINATION-WALL] THREAT DETECTED: {rep.threat_type}")
            print(f"   {rep.message}")
            return 1
        print(f"✅ [AI-HALLUCINATION-WALL] Package '{args.name}' appears legitimate.")
        return 0

    return 0

if __name__ == "__main__":
    sys.exit(main())
