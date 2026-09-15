"""Interpret the pinned mtg 2.2.8 doctor contract without logging credentials.

Doctor exits 1 for advisory clock drift, unavailable public-IP discovery and
a third-party masking domain not resolving to the proxy's own IP. These do
not mean that MTProto cannot start: IP discovery serves the SNI-DNS comparison.
Configuration errors, failed connections, excessive drift and unknown output
remain fatal. We do not change time tolerances or falsify the public IP.
"""

from settings import StackError


def check_mtg_diagnostics(report):
    headers = ("Deprecated options", "Time skewness", "Validate native network connectivity",
               "Validate fronting domain connectivity", "Validate SNI-DNS match")
    sections, current = {}, None
    for line in report.splitlines():
        if line in headers:
            current = line
            sections[current] = []
        elif current and line.startswith("  "):
            sections[current].append(line.strip())
        elif line.strip():
            raise StackError("Unrecognized MTProto diagnostic output")
    if set(sections) != set(headers) or any(not entries for entries in sections.values()):
        raise StackError("Incomplete MTProto diagnostics; configuration or command failed")
    for header in headers[:-1]:
        for entry in sections[header]:
            if entry.startswith("✅"):
                continue
            if header == "Time skewness" and entry.startswith("⚠️ Time drift is "):
                print("MTProto: clock drift advisory; check host time synchronization.", flush=True)
                continue
            raise StackError(f"MTProto diagnostics failed: {header}")
    if len(sections["Validate native network connectivity"]) != 6:
        raise StackError("Incomplete Telegram data-center connectivity checks")
    for entry in sections[headers[-1]]:
        if entry.startswith("✅"):
            continue
        if entry == ("‼️ cannot detect public IP address: cannot detect automatically "
                     "and public-ipv4/public-ipv6 are not set in config"):
            print("MTProto: public IP lookup unavailable; SNI-DNS comparison skipped (advisory).", flush=True)
            continue
        if entry.startswith("❌ Hostname ") and "is resolved to " in entry and " addresses, not " in entry:
            print("MTProto: third-party masking domain has a different IP (advisory).", flush=True)
            continue
        if entry.startswith("‼️ cannot resolve DNS name of ") or (
                entry.startswith("❌ Hostname ") and entry.endswith(" cannot be resolved to any host")):
            raise StackError("MTProto masking hostname DNS lookup failed")
        raise StackError("Unrecognized MTProto SNI-DNS diagnostic output")
