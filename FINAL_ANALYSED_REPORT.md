# Cyber Threat Suite — Final Analysed Report

**Project:** Cyber Threat Suite (HTML version, `index.html`)
**Method:** Rule-based analysis only — no AI, no ML, no model, no training, no prediction.
**How verdicts are decided:** Local IOC list + fixed thresholds + pattern matching.
Clean = no rule fired. Suspicious = suspicious pattern, no confirmed IOC.
Malicious = IOC match, or 5+ failed logins in 5 minutes, or success after failures.
**Test data:** Safe lab samples only (TEST-NET IPs, `.example` domains, EICAR test hash).
All files were uploaded and checked in the HTML Windows Log analyzer.

## 1. Summary Table — One Row Per Log File

| # | Log File | Lines | Failed Logons (4625) | Brute Force | Success After Failures | Final Verdict |
|---|----------|-------|----------------------|-------------|------------------------|---------------|
| 1 | attack_log.txt | 10 | 6 | Yes | Yes | Malicious |
| 2 | clean_log.txt | 5 | 0 | No | No | Clean |
| 3 | bruteforce_log.txt | 7 | 7 | Yes | No | Malicious |
| 4 | powershell_log.txt | 4 | 0 | No | No | Suspicious |

## 2. Detailed Findings Table — Every Finding, With MITRE Mapping

| # | Log File | Finding | Severity / Verdict | MITRE ATT&CK | Evidence in Log | Recommended Response |
|---|----------|---------|--------------------|--------------|-----------------|----------------------|
| 1 | attack_log.txt | Brute-force pattern: 5+ failures inside 5 minutes | Malicious | T1110.001 Password Guessing | 6 x 4625 for labtest, 10:01–10:03 | Reset password, limit source IP |
| 2 | attack_log.txt | Successful login after multiple failures | Malicious | T1078 Valid Accounts | 4624 at 10:04 after 6 failures | Treat as possible compromise, force password change |
| 3 | attack_log.txt | Suspicious PowerShell activity | Suspicious | T1059.001 PowerShell | powershell -EncodedCommand at 10:05 | Check parent process and full command line |
| 4 | attack_log.txt | Possible privilege escalation | Suspicious | T1098 Account Manipulation | 4732, labtest added to Administrators at 10:06 | Remove test user from Administrators |
| 5 | attack_log.txt | Unusual network connection | Suspicious | T1095 Non-Application Layer Protocol | Connection on port 4444 at 10:07 | Check process, block destination in lab firewall |
| 6 | attack_log.txt | Known malicious IP in log | Malicious | T1071.001 Web Protocols | IOC IP 198.51.100.99 at 10:07 | Isolate host in lab, preserve logs |
| 7 | clean_log.txt | No suspicious pattern found | Clean | — | 5 lines, only 4624 successes and port 443 traffic | No action needed |
| 8 | bruteforce_log.txt | Brute-force pattern: 5+ failures inside 5 minutes | Malicious | T1110.001 Password Guessing | 7 x 4625 for labtest, 11:00–11:04, no success | Reset password, limit source IP, check lockout |
| 9 | powershell_log.txt | Suspicious PowerShell activity | Suspicious | T1059.001 PowerShell | -ExecutionPolicy Bypass at 12:05 | Check parent process, do not run unknown scripts |
| 10 | powershell_log.txt | Suspicious PowerShell activity | Suspicious | T1059.001 PowerShell | -EncodedCommand at 12:06 | Inspect script block, check network activity |
| 11 | powershell_log.txt | Suspicious PowerShell activity | Suspicious | T1059.001 PowerShell | DownloadString at 12:07 | Block download source, check downloaded file hash |

## 3. MITRE ATT&CK Distribution Table

| MITRE Technique | Technique Name | Count of Findings | Log Files |
|-----------------|----------------|-------------------|-----------|
| T1110.001 | Brute Force: Password Guessing | 2 | attack_log.txt, bruteforce_log.txt |
| T1078 | Valid Accounts | 1 | attack_log.txt |
| T1059.001 | PowerShell | 4 | attack_log.txt, powershell_log.txt (x3) |
| T1098 | Account Manipulation | 1 | attack_log.txt |
| T1095 | Non-Application Layer Protocol | 1 | attack_log.txt |
| T1071.001 | Application Layer Protocol: Web Protocols | 1 | attack_log.txt |
| — | No technique (Clean) | 1 | clean_log.txt |

## 4. Conclusion Table — What This Proves

| Question for Viva | Answer |
|-------------------|--------|
| Does this use AI/ML? | No. Only if-else rules, IOC matching, counting, and regex pattern matching. |
| How is brute force detected? | By counting 4625 events and checking if 5+ fall inside a 5-minute window. |
| How is a file/IP judged malicious? | By matching it against a known IOC list, not by prediction. |
| What does the analyst do next? | Follow the Recommended Response column: reset, block, isolate, or close as Clean. |
| Overall result | 2 Malicious logs, 1 Suspicious log, 1 Clean log — the suite separates normal activity from attack activity using rules alone. |

## Files Tested

- `samples/attack_log.txt`
- `samples/clean_log.txt`
- `samples/bruteforce_log.txt`
- `samples/powershell_log.txt`

All are safe lab data. No real system, account, or malicious file was used.
