# SOC Analyst Portfolio

Hands-on security analysis portfolio focused on **SOC Level 1 / Junior Security Analyst** workflows.

> **Transparency:** All material currently in this repository is a **synthetic training scenario**, not a real-world customer incident or completed LetsDefend lab. Synthetic IPs and fabricated logs are marked as such.

## Investigations

| Case | Focus | Status |
|---|---|---|
| [01 — Suspicious PowerShell & Windows Service Persistence](investigations/01-windows-persistence/README.md) | Windows Event Logs, Sysmon, persistence, MITRE ATT&CK | Completed simulation |
| [02 — Phishing Email Analysis](investigations/02-phishing-analysis/README.md) | Email headers, URLs, attachments | Planned |
| [03 — Suspicious PowerShell](investigations/03-suspicious-powershell/README.md) | Script block logging, process ancestry | Planned |

## Skills demonstrated
- Triaging Windows events 4688, 7045, PowerShell 4104 and Sysmon 1/3
- Building a process timeline and distinguishing evidence from hypotheses
- Identifying persistence mechanisms and mapping to MITRE ATT&CK
- Recording indicators and escalating findings with a concise incident report

## Repository layout
- `investigations/` — case writeups and sanitized/synthetic evidence
- `templates/` — reusable case report template
- `queries/` — starter detection/triage searches

## Workflow
1. Define the alert and scope.
2. Review events and verify host, user, timestamps and process lineage.
3. Build a timeline; identify suspicious behavior and alternative explanations.
4. Document indicators and MITRE mappings.
5. Recommend containment/escalation according to company playbooks.

## Ethical handling
Do not upload corporate logs, customer details, live credentials, malicious binaries or data from commercial labs unless redistribution is explicitly permitted. Prefer your own notes and sanitized examples.
