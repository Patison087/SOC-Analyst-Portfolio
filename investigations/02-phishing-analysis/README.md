Case 02 — Phishing Email Investigation (LetsDefend SOC101)
Hands-on training exercise, not a real production incident. This report is based on the events visible during the investigation. Endpoint compromise is not confirmed.

Executive summary
A suspicious email containing an external HTTP URL was allowed by the mail system. Roughly ten minutes later, the proxy recorded an allowed request to that same URL from endpoint MarkPRD (172.16.17.88) associated with chrome.exe. This confirms a relevant web request, not that the recipient clicked the email link, that a page loaded, or that malware executed.

Assessment: Suspicious message and related network request confirmed; impact undetermined. The final training-platform verdict has not yet been submitted.
Email alert
Field	Observed value
Alert	SOC101 — Phishing Mail Detected (Event ID 87)
Severity	Medium
Time	2021-04-04 23:00:15 (+03:00, as displayed in Monitoring)
Alert type	Exchange
Mail device action	Allowed
Sender	lethuyan852@gmail.com
Recipient	mark@letsdefend.io
Subject	Its a Must have for your Phone
Sender IP shown	146.56.195.192
URL (domain defanged)	http://nuangaybantiep[.]xyz
Email Security action	Unknown


Email text: “Check out this product! Your life will be less difficult.”
Proxy log: positive correlation
In Log Management, Source Address contains "nuangaybantiep.xyz" returned 0 results. Switching to Raw Log contains "nuangaybantiep.xyz" returned 1 event.
Field	Observed value
Event time	2021-04-04 23:10:10 (timezone not separately verified)
Type	Proxy
Source IP / port	172.16.17.88:39483
Destination IP / port	192.64.119.190:80
Process	chrome.exe
Requested URL	http://nuangaybantiep[.]xyz
Action	Allowed


Transport security observation: The requested URL explicitly uses http:// and the proxy destination port is 80, indicating plain HTTP rather than HTTPS/TLS for this logged request. HTTP does not provide transport encryption or server authentication, so traffic may be exposed to interception or modification in transit. This is a security concern, but HTTP alone does not prove phishing or malware. The domain is defanged with [.] to avoid accidental access.

The displayed timestamps are 9 minutes 55 seconds apart, assuming the same timezone. An allowed request does not prove a successful HTTP response or a download.
Endpoint investigation
Endpoint Security maps 172.16.17.88 to MarkPRD.
Data source	Observation	Limitation
Processes	16 listed, including chrome.exe, OUTLOOK.exe, wmic.exe, bcdedit.exe, wbadmin.exe	No usable PID, execution time, or command line in visible rows
Browser History	No records shown	Does not disprove proxy activity
Network Action	No records shown	Separate telemetry source
Terminal History	No records shown	Cannot establish absence of commands


The device name does not by itself identify the logged-in user who generated the HTTP request.
Timeline
1. 23:00:15: Exchange alert for the suspicious email containing the URL.
2. 23:10:10: Proxy recorded an HTTP request to the same URL from 172.16.17.88, associated with chrome.exe.
Observed indicators (not independently verified as malicious)
- Domain: nuangaybantiep[.]xyz
- URL: http://nuangaybantiep[.]xyz
- Destination IP: 192.64.119.190
- SMTP sender IP shown in lab: 146.56.195.192
- Endpoint: MarkPRD / 172.16.17.88
No real reputation-check result, attachment hash, or SPF/DKIM/DMARC findings were collected during this investigation.
Findings and disposition
Confirmed: A suspicious email was allowed; a later proxy log shows an HTTP request to the same domain from MarkPRD.

Not confirmed: User click, successful page loading, malware download/execution, credential theft, endpoint compromise.

Recommended escalation: Confirm who used the host, examine HTTP response/redirect/download and DNS records if accessible, check reputation safely, hunt for other recipients or network connections, and follow the local response playbook. Do not assert the host is clean on the basis of empty endpoint tabs.
Lessons learned
- Choosing the correct search field matters: raw_log contained the domain, while source_address did not.
- Correlate signals across email, proxy, and endpoint sources.
- Record insecure HTTP transport (http://, TCP/80) as context, not as standalone proof of malicious activity.
- Keep observed facts separate from hypotheses and missing telemetry.
- 
This is an original summary of a LetsDefend training investigation, not a copy of the full lab material.
