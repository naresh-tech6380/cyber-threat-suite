# Cyber Threat Suite

A web-based cyber threat analyzer. Analysis only — no AI, no ML, no model, no training, no prediction.

## What it does

- **IP analyzer** — checks an IP against a local IOC list and rule thresholds
- **Domain / URL analyzer** — checks domains and URLs for phishing keywords, plain-HTTP login pages, and known patterns
- **File hash analyzer** — checks MD5 / SHA-256 hashes, including the EICAR test hash
- **Windows log analyzer** — paste log text, or upload a `.txt`, `.log`, or `.csv` log file (read locally in the browser, never sent to a server)

Every finding shows:
- The exact rule that fired
- A verdict: Clean / Suspicious / Malicious
- A MITRE ATT&CK technique (for example T1110.001 brute force, T1059.001 PowerShell, T1078 valid accounts, T1098 account manipulation)
- A recommended response

Log rules include: failed logons (4625), brute force (5+ failures in 5 minutes), success after failures (4624), suspicious PowerShell (-EncodedCommand / Bypass / DownloadString / IEX), process creation (4688 / Sysmon 1), unusual ports, IOC destinations, and privilege escalation (4672 / 4732).

## How to run

No server, no install, no API key needed for the built-in rule-based analysis:

1. Open `index.html` in any browser, or
2. Host it with GitHub Pages from this repo, or
3. Run it in VS Code — see [RUN_IN_VSCODE.md](RUN_IN_VSCODE.md):
   clone the repo, open the folder in VS Code, install Live Server,
   right-click `index.html` > Open with Live Server.

Try the sample buttons first — they use safe lab data only (TEST-NET IPs, `.example` domains, the EICAR test hash, and sample log sequences).

## How to explain it to a professor

> This suite does not use AI/ML. It performs threat analysis like a SOC analyst, by matching indicators against threat intelligence and predefined rules.

## Project structure

- `index.html` — the complete Cyber Threat Suite web app (HTML + CSS + JavaScript, single file)
- `samples/` — add your own safe lab log samples here if you want them in the repo

## Safety note

All samples are safe lab data. Do not test this against real systems, real accounts, or real malicious files. Use only your own isolated lab VM.
