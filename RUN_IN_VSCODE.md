# Run Cyber Threat Suite in VS Code

No install, no server code, no API key needed. This is a single-file web app.

## Option 1 — Easiest (recommended)

1. Clone this repo, or download it as ZIP and extract it:
   ```
   git clone https://github.com/naresh-tech6380/cyber-threat-suite.git
   ```
2. Open VS Code, then File > Open Folder > select the `cyber-threat-suite` folder.
3. Install the **Live Server** extension in VS Code (by Ritwick Dey).
4. Right-click `index.html` > **Open with Live Server**.
5. Your browser opens at `http://127.0.0.1:5500/` — the suite is running.

## Option 2 — Without any extension

1. Open the folder in VS Code as above.
2. Right-click `index.html` > Open in browser, or just double-click `index.html` in your file manager.
3. Everything works — all analysis runs locally in your browser.

## Option 3 — With Python (if you have Python)

In the VS Code terminal, from inside the `cyber-threat-suite` folder:
```
python -m http.server 8000
```
Then open `http://localhost:8000/` in your browser.

## How to test it

1. Click a sample button in any analyzer (IP, Domain/URL, Hash, Windows Log).
2. Or go to Windows Log > Choose log file, upload a `.txt`, `.log`, or `.csv` file.
   The file is read locally in your browser only — it is never sent to a server.
3. Check the verdict (Clean / Suspicious / Malicious), the rule that fired,
   the MITRE ATT&CK technique, and download the report.

## Notes for your professor

- Analysis only, no AI/ML, no model, no training, no prediction.
- Verdicts come from fixed if-else rules and a local IOC list.
- All samples use safe lab data (TEST-NET IPs, `.example` domains, EICAR test hash).
