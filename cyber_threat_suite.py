"""
Cyber Threat Suite - Python version
====================================
Analysis ONLY. No AI, no ML, no model, no training, no prediction.

This tool checks a threat indicator against fixed rules and a local
IOC list, exactly like a SOC analyst does, and returns:
    Clean / Suspicious / Malicious
plus the MITRE ATT&CK technique and a recommended response.

Analyzers:
    1. IP address
    2. Domain / URL
    3. File hash (MD5 / SHA-256)
    4. Windows log file (.txt / .log / .csv)

Only the Python standard library is used. No external packages.
No data is sent anywhere - all analysis is local.

Usage (in VS Code terminal, from this folder):
    python cyber_threat_suite.py --demo
    python cyber_threat_suite.py --ip 198.51.100.99
    python cyber_threat_suite.py --domain example-phishing-login.example
    python cyber_threat_suite.py --url http://login.example/verify
    python cyber_threat_suite.py --hash 44d88612fea8a8f36de82e1278abb02
    python cyber_threat_suite.py --log samples/sample_attack.log
    python cyber_threat_suite.py --log mylog.txt --report report.txt
"""

import argparse
import ipaddress
import re
import sys
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Local IOC list - SAFE LAB DATA ONLY.
# These are TEST-NET documentation addresses and example domains,
# used so the demo works without touching any real malicious infrastructure.
# In a real SOC this list would come from VirusTotal / threat feeds.
# ---------------------------------------------------------------------------
MALICIOUS_IPS = {
    "198.51.100.99": "Sample IOC - test malicious IP (TEST-NET-2)",
    "203.0.113.99": "Sample IOC - test malicious IP (TEST-NET-3)",
}

MALICIOUS_DOMAINS = {
    "malicious.example",
    "phishing-login.example",
    "free-prize-verify.example",
}

# EICAR test file - industry-standard antivirus test string, NOT malware.
# MD5 below is the published EICAR MD5.
KNOWN_BAD_HASHES = {
    "44d88612fea8a8f36de82e1278abb02": "EICAR test file (antivirus test string, not real malware)",
}

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "password",
    "free-prize", "prize", "gift", "bank", "update-payment",
]

SUSPICIOUS_PORTS = {4444, 4443, 8080, 1337, 31337, 5555}

POWERSHELL_FLAGS = [
    "-encodedcommand", "-enc", "-executionpolicy bypass",
    "downloadstring", "iex", "invoke-expression",
    "frombase64string", "-windowstyle hidden",
]


def verdict_rank(verdict):
    return {"Clean": 0, "Suspicious": 1, "Malicious": 2}[verdict]


def worst_verdict(verdicts):
    """Return the highest-severity verdict from a list."""
    result = "Clean"
    for v in verdicts:
        if verdict_rank(v) > verdict_rank(result):
            result = v
    return result


def make_finding(rule, verdict, mitre, detail, response):
    return {
        "rule": rule,
        "verdict": verdict,
        "mitre": mitre,
        "detail": detail,
        "response": response,
    }


# ---------------------------------------------------------------------------
# 1. IP analyzer
# ---------------------------------------------------------------------------
def analyze_ip(ip_str):
    findings = []
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return "Suspicious", [make_finding(
            "Invalid IP format", "Suspicious", "T1071",
            f"'{ip_str}' is not a valid IP address.",
            "Check the input and try again.")]

    if ip_str in MALICIOUS_IPS:
        findings.append(make_finding(
            "IOC match - known malicious IP", "Malicious", "T1071.001",
            f"{ip_str} is in the local IOC list: {MALICIOUS_IPS[ip_str]}",
            "Block this IP in the firewall and check for connections to it."))
    elif ip.is_private:
        findings.append(make_finding(
            "Private IP address", "Clean", "-",
            f"{ip_str} is a private/internal IP.",
            "No external action needed. Investigate only if it appears in unexpected logs."))
    elif ip.is_reserved or ip.is_loopback or ip.is_link_local:
        findings.append(make_finding(
            "Reserved / special IP", "Suspicious", "T1071",
            f"{ip_str} is a reserved/special address, not normal public traffic.",
            "Check which process tried to reach it and why."))
    else:
        findings.append(make_finding(
            "No IOC match", "Clean", "-",
            f"{ip_str} is not in the local IOC list.",
            "No action needed from this check alone. In a live SOC, also check VirusTotal."))

    return worst_verdict([f["verdict"] for f in findings]), findings


# ---------------------------------------------------------------------------
# 2. Domain / URL analyzer
# ---------------------------------------------------------------------------
def analyze_domain_or_url(value, is_url=False):
    findings = []
    text = value.strip().lower()

    for domain in MALICIOUS_DOMAINS:
        if domain in text:
            findings.append(make_finding(
                "IOC match - known malicious domain", "Malicious", "T1566.002",
                f"'{domain}' is in the local IOC list.",
                "Block this domain and check who visited it."))
            return "Malicious", findings

    hits = [k for k in PHISHING_KEYWORDS if k in text]
    if hits:
        findings.append(make_finding(
            "Phishing keyword in domain/URL", "Suspicious", "T1566.002",
            f"Phishing-style keywords found: {', '.join(hits)}",
            "Do not log in through this link. Verify the sender separately."))

    if is_url and text.startswith("http://"):
        findings.append(make_finding(
            "Login-style page over plain HTTP", "Suspicious", "T1566.002",
            "URL uses http://, not https://, so credentials would travel in clear text.",
            "Do not enter credentials. Prefer the official https site."))

    if not findings:
        findings.append(make_finding(
            "No IOC or phishing pattern match", "Clean", "-",
            f"'{value}' matches no local IOC or phishing rule.",
            "No action needed from this check alone."))

    return worst_verdict([f["verdict"] for f in findings]), findings


# ---------------------------------------------------------------------------
# 3. File hash analyzer
# ---------------------------------------------------------------------------
def analyze_hash(hash_str):
    h = hash_str.strip().lower()
    findings = []

    if h in KNOWN_BAD_HASHES:
        findings.append(make_finding(
            "Hash match - known test/bad file", "Malicious", "T1204.002",
            f"Hash matches: {KNOWN_BAD_HASHES[h]}",
            "Quarantine the file, do not run it, and check how it arrived."))
        return "Malicious", findings

    if re.fullmatch(r"[0-9a-f]{32}", h):
        kind = "MD5"
    elif re.fullmatch(r"[0-9a-f]{64}", h):
        kind = "SHA-256"
    else:
        return "Suspicious", [make_finding(
            "Invalid hash format", "Suspicious", "T1204.002",
            "Hash is not a valid 32-char MD5 or 64-char SHA-256 hex string.",
            "Copy the hash again from your file properties or hash tool.")]

    findings.append(make_finding(
        f"No match in local hash list ({kind})", "Clean", "-",
        f"{kind} hash is not in the local known-bad list.",
        "No action needed from this check alone. In a live SOC, also check VirusTotal."))
    return "Clean", findings


# ---------------------------------------------------------------------------
# 4. Windows log analyzer
# ---------------------------------------------------------------------------
TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
EVENT_RE = re.compile(r"\b(4625|4624|4672|4732|4688)\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_timestamp(line):
    m = TIMESTAMP_RE.search(line)
    if not m:
        return None
    text = m.group(1).replace("T", " ")
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def analyze_log_text(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    findings = []
    failed = []          # (timestamp, user, ip) for 4625
    success_after = False
    failed_count = 0

    for line in lines:
        low = line.lower()
        ts = parse_timestamp(line)
        events = EVENT_RE.findall(line)

        if "4625" in events:
            failed_count += 1
            user_m = re.search(r"user[=:\s]+([A-Za-z0-9_.\-]+)", line, re.I)
            ip_m = IP_RE.search(line)
            failed.append((ts, user_m.group(1) if user_m else "?",
                           ip_m.group(0) if ip_m else "?"))

        if "4624" in events and failed_count > 0:
            success_after = True

        if "4672" in events or "4732" in events:
            findings.append(make_finding(
                "Possible privilege escalation", "Suspicious",
                "T1098",
                f"Event 4672/4732 in line: {line.strip()[:120]}",
                "Check who was added to Administrators and remove test users if needed."))

        if any(flag in low for flag in POWERSHELL_FLAGS) or "powershell" in low and (
                "encoded" in low or "bypass" in low or "downloadstring" in low):
            findings.append(make_finding(
                "Suspicious PowerShell activity", "Suspicious", "T1059.001",
                f"PowerShell pattern in line: {line.strip()[:120]}",
                "Check the parent process and full command line, then kill it in the lab if unknown."))

        if "4688" in events or "sysmon 1" in low or "process created" in low:
            findings.append(make_finding(
                "New process creation", "Suspicious", "T1059",
                f"Process creation in line: {line.strip()[:120]}",
                "Check parent process, hash and command line."))

        for port in SUSPICIOUS_PORTS:
            if f":{port}" in line or f"port {port}" in low or f"port={port}" in low:
                findings.append(make_finding(
                    "Unusual network connection", "Suspicious", "T1095",
                    f"Unusual port {port} in line: {line.strip()[:120]}",
                    "Check which process made the connection and block the destination in the lab firewall."))

        for ip in MALICIOUS_IPS:
            if ip in line:
                findings.append(make_finding(
                    "Known malicious IP in log", "Malicious", "T1071.001",
                    f"IOC IP {ip} appears in line: {line.strip()[:120]}",
                    "Isolate the host in the lab and preserve the logs."))

    # Brute force: 5+ failures in a 5-minute sliding window (timestamps),
    # or 5+ failures total if the log has no timestamps.
    brute_force = False
    if failed:
        dated = [f for f in failed if f[0] is not None]
        if dated:
            dated.sort(key=lambda x: x[0])
            for i in range(len(dated)):
                window = [f for f in dated
                          if (f[0] - dated[i][0]).total_seconds() <= 300]
                if len(window) >= 5:
                    brute_force = True
                    break
        elif len(failed) >= 5:
            brute_force = True

    if brute_force:
        findings.append(make_finding(
            "Brute-force pattern: 5+ failures inside 5 minutes",
            "Malicious", "T1110.001",
            f"{failed_count} failed logons (4625) in the log, with 5+ inside 5 minutes.",
            "Reset the account password, check for a success after the failures, and limit the source."))
    elif failed_count > 0:
        findings.append(make_finding(
            "Failed logon attempts", "Suspicious", "T1110.001",
            f"{failed_count} failed logon(s) (4625) in the log.",
            "Verify the user is real and watch for more failures."))

    if success_after and failed_count >= 5:
        findings.append(make_finding(
            "Successful login after multiple failures", "Malicious", "T1078",
            "A 4624 success appears after 5+ failures for the same account pattern.",
            "Treat as possible compromise until proven to be a lab test. Force a password change."))

    if not findings:
        findings.append(make_finding(
            "No suspicious pattern found", "Clean", "-",
            f"{len(lines)} log line(s) checked, no rule fired.",
            "No action needed."))

    verdict = worst_verdict([f["verdict"] for f in findings])
    summary = {
        "lines": len(lines),
        "failed_logons": failed_count,
        "brute_force": brute_force,
        "success_after_failures": success_after,
    }
    return verdict, findings, summary


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def print_result(title, verdict, findings, extra=None):
    print("=" * 64)
    print(f"{title}")
    print(f"Verdict: {verdict}")
    if extra:
        for k, v in extra.items():
            print(f"{k}: {v}")
    print("-" * 64)
    for f in findings:
        print(f"[{f['verdict']}] {f['rule']}")
        print(f"  MITRE: {f['mitre']}")
        print(f"  Detail: {f['detail']}")
        print(f"  Response: {f['response']}")
    print()


def build_report(results):
    out = ["CYBER THREAT SUITE - ANALYSIS REPORT (rule-based, no AI/ML)", ""]
    for title, verdict, findings in results:
        out.append(f"{title} -> {verdict}")
        for f in findings:
            out.append(f"  [{f['verdict']}] {f['rule']} | MITRE {f['mitre']} | {f['detail']}")
        out.append("")
    return "\n".join(out)


def run_demo():
    results = []

    v, f = analyze_ip("198.51.100.99")
    print_result("IP: 198.51.100.99 (sample IOC)", v, f)
    results.append(("IP 198.51.100.99", v, f))

    v, f = analyze_domain_or_url("http://login.example/verify", is_url=True)
    print_result("URL: http://login.example/verify (sample)", v, f)
    results.append(("URL http://login.example/verify", v, f))

    v, f = analyze_hash("44d88612fea8a8f36de82e1278abb02")
    print_result("Hash: EICAR MD5 (sample)", v, f)
    results.append(("Hash EICAR MD5", v, f))

    sample_log = """2026-10-26 10:01:00 4625 user=labtest ip=203.0.113.10
2026-10-26 10:01:30 4625 user=labtest ip=203.0.113.10
2026-10-26 10:02:00 4625 user=labtest ip=203.0.113.10
2026-10-26 10:02:30 4625 user=labtest ip=203.0.113.10
2026-10-26 10:03:00 4625 user=labtest ip=203.0.113.10
2026-10-26 10:03:30 4625 user=labtest ip=203.0.113.10
2026-10-26 10:04:00 4624 user=labtest ip=203.0.113.10
2026-10-26 10:05:00 powershell -EncodedCommand dGVzdA==
2026-10-26 10:06:00 4732 user=labtest added to Administrators
"""
    v, f, s = analyze_log_text(sample_log)
    print_result("Log: sample attack sequence", v, f, extra=s)
    results.append(("Log sample attack sequence", v, f))

    print(build_report(results))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Cyber Threat Suite - rule-based analyzer, no AI/ML.")
    parser.add_argument("--demo", action="store_true", help="Run safe sample analyses")
    parser.add_argument("--ip", help="Analyze an IP address")
    parser.add_argument("--domain", help="Analyze a domain")
    parser.add_argument("--url", help="Analyze a URL")
    parser.add_argument("--hash", help="Analyze an MD5 or SHA-256 hash")
    parser.add_argument("--log", help="Analyze a Windows log file (.txt/.log/.csv)")
    parser.add_argument("--report", help="Write the report to this file")
    args = parser.parse_args(argv)

    if args.demo:
        run_demo()
        return 0

    results = []
    if args.ip:
        v, f = analyze_ip(args.ip)
        print_result(f"IP: {args.ip}", v, f)
        results.append((f"IP {args.ip}", v, f))
    if args.domain:
        v, f = analyze_domain_or_url(args.domain)
        print_result(f"Domain: {args.domain}", v, f)
        results.append((f"Domain {args.domain}", v, f))
    if args.url:
        v, f = analyze_domain_or_url(args.url, is_url=True)
        print_result(f"URL: {args.url}", v, f)
        results.append((f"URL {args.url}", v, f))
    if args.hash:
        v, f = analyze_hash(args.hash)
        print_result(f"Hash: {args.hash}", v, f)
        results.append((f"Hash {args.hash}", v, f))
    if args.log:
        try:
            with open(args.log, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"Could not read log file: {exc}", file=sys.stderr)
            return 1
        v, f, s = analyze_log_text(text)
        print_result(f"Log file: {args.log}", v, f, extra=s)
        results.append((f"Log file {args.log}", v, f))

    if not results:
        parser.print_help()
        print("\nTry: python cyber_threat_suite.py --demo")
        return 0

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(build_report(results))
        print(f"Report written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
