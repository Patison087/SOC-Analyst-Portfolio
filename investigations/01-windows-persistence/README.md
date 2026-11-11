# Case 01 — Suspicious PowerShell Execution and Windows Service Persistence

**Type:** Synthetic training case (constructed for SOC L1 learning)  
**Priority:** High (training triage recommendation)  
**Asset:** WIN-WS023 (fictional)  
**Status:** Escalate to SOC L2 / incident response

## 1. Alert summary
A Microsoft Word process launched PowerShell, which ran a script that downloaded an executable to `C:\Users\Public\svchost.exe`. A new auto-start Windows service referenced the same path; subsequent outgoing TCP connection was observed. These indicators collectively suggest execution and persistence, subject to validation.

## 2. Evidence and timeline

All UTC times and examples are synthetic. Evidence is reconstructed for training rather than extracted from an actual endpoint.

| UTC | Source / Event ID | Observation | Analyst interpretation |
|---|---|---|---|
| 09:14:18 | File-open observation (illustrative) | `Invoice_November.docm` opened | Document could be an initial vector; provenance unverified |
| 09:14:23 | Sysmon 1 / Security 4688 | `WINWORD.EXE` spawned `powershell.exe` | Unusual Office-to-shell ancestry |
| 09:14:25 | PowerShell 4104 | Script downloaded `payload.exe` as `C:\Users\Public\svchost.exe` | Masquerading and payload staging |
| 09:14:30 | Process creation (illustrative) | `C:\Users\Public\svchost.exe` executed | Executable may be unauthorized |
| Time not supplied | System 7045 | `WindowsUpdateHelper` service installed, auto-start under `LocalSystem` | Potential service-based persistence |
| Time not supplied | Sysmon 3 | PID 4820 -> `203.0.113.50:443` | Outbound communication; content and purpose unknown |

See [`evidence/synthetic-events.md`](evidence/synthetic-events.md) for examples.

## 3. Why suspicious
- A copy named `svchost.exe` in `C:\Users\Public\` is outside the expected Windows system directory.
- Office application launching a shell shortly after a document is opened warrants investigation.
- `-ExecutionPolicy Bypass` alone is **not** proof of malicious activity, but adds context to the observed download/execution chain.
- Automatic service start and `LocalSystem` create a plausible persistence and privilege exposure path.
- TCP/443 is common for legitimate HTTPS; destination reputation by itself is insufficient to decide the case.

## 4. MITRE ATT&CK hypotheses
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1543.003** — Create or Modify System Process: Windows Service

**Not yet confirmed:** Phishing initial access, macro execution, command-and-control activity or exfiltration. The `.docm` extension and network connection alone do not prove these mechanisms.

## 5. Indicators to collect / validate
| Type | Value | Notes |
|---|---|---|
| Host | `WIN-WS023` | Fictional hostname |
| File path | `C:\Users\Public\svchost.exe` | Verify SHA-256, signer, creation time |
| Script path | `C:\Users\Public\update.ps1` | Preserve content securely |
| Service name | `WindowsUpdateHelper` | Verify service definition and creation context |
| PID | `4820` | Correlate with ProcessGuid and time; PIDs are reused |
| Destination | `203.0.113.50:443` | **TEST-NET-3 documentation address**, not a live malicious IOC |
| Document | `Invoice_November.docm` | Validate source and attachment history |

## 6. Recommended SOC L1 actions
1. Validate event sources, timestamps, actual host identity and the process tree.
2. Collect hashes, service configuration, signer, command lines, related events and authorized-change context.
3. Search other endpoints for matching service names, paths, hashes and event patterns.
4. Preserve evidence and notify SOC L2; recommend host isolation according to IR policy and severity criteria.
5. Do **not** execute suspicious scripts or binaries on an analyst workstation.

## 7. Remaining questions
- Where did the document come from? Was it an email attachment or a download?
- Did a macro, exploit, add-in or other mechanism launch PowerShell?
- Who or what installed the service, and was it authorized?
- What is the SHA-256 of the executable and is it signed?
- Was there lateral movement, additional persistence or data access?

## 8. Analyst conclusion
**Assessment:** High-confidence suspicious execution and likely persistence in the context of this synthetic scenario. **Impact and initial access remain unconfirmed.** Escalation is warranted; no claim of a completed forensic investigation is made.

## 9. What I practiced
Process ancestry, event correlation, separating observed facts from hypotheses, documenting IOCs and actionable SOC L1 escalation.
