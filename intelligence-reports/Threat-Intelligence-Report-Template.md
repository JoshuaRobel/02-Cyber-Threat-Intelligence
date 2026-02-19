# Threat Intelligence Report Template & Examples

**Version:** 1.2  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Intelligence Report Structure

### Executive Summary

```
THREAT INTELLIGENCE REPORT
Date: 2026-02-19
Classification: INTERNAL USE

TITLE: APT28 Campaign Targeting Energy Sector

Executive Summary:
We have identified a sophisticated campaign attributed to APT28 (Fancy Bear) targeting 
energy sector organizations across North America and Western Europe. The campaign uses 
spear-phishing emails and Zero-day exploits to establish initial access. Over 200+ 
organizations attempted targeting, with 15+ successful compromises confirmed.

KEY FINDINGS:
├─ Threat actor: APT28 (GRU Unit 26165)
├─ Motivation: Strategic espionage (energy policy intelligence)
├─ Timeline: Campaign active since 2025-12-01
├─ Scope: Global (North America, Europe, Middle East)
├─ Success rate: 7% (15 successful compromises out of 200+ attempted)
├─ Capabilities: Advanced exploitation, custom malware, persistence
└─ Risk level: CRITICAL (state-sponsored, advanced tradecraft)

Recommended Actions:
├─ IMMEDIATE: Check for indicators of compromise
├─ SHORT-TERM: Patch identified vulnerabilities
├─ LONG-TERM: Increase monitoring for APT28 tradecraft
└─ REPORT: Share with industry partners and government agencies
```

### Campaign Analysis

```
CAMPAIGN DETAILS:

Campaign Name: "Winter Energy"
Duration: 2025-12-01 → Present (2.5 months active)
Targeting: Energy sector (electricity, oil & gas, nuclear)
Geographic scope: 12 countries
Organizations targeted: 247 (estimated)
Successful breaches: 15+ confirmed

Attack methodology:
├─ Phase 1 (Reconnaissance): LinkedIn profiling of target organizations
├─ Phase 2 (Weaponization): Custom malware development (Sofacy variant)
├─ Phase 3 (Delivery): Highly targeted spear-phishing (1-3 per organization)
├─ Phase 4 (Exploitation): CVE-2025-9876 zero-day (Office document exploit)
├─ Phase 5 (Installation): C2 beaconing to attacker infrastructure
├─ Phase 6 (Lateral movement): Enumeration and privilege escalation
└─ Phase 7 (Exfiltration): Bulk data theft (strategy documents, communications)

Data targeted:
├─ Strategic planning documents
├─ Energy policy communications
├─ Executive meeting notes
├─ Government liaison contact information
├─ Critical infrastructure technical details
└─ Estimated data loss: 50+ GB of sensitive documents
```

### Indicators of Compromise (IOCs)

```
FILE INDICATORS:
├─ MD5: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
│  └─ File: sofacy.exe (14 KB)
│  └─ Detection: 42/70 VirusTotal engines
│
├─ MD5: b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7
│  └─ File: document_2026.docm (2.3 MB)
│  └─ Detection: 35/70 VirusTotal engines (malicious macro)
└─ Detection: Hash-based signatures (add to antivirus)

NETWORK INDICATORS:
├─ C2 Server: 203.0.113.42 (Moscow, AS25 Rostelecom)
│  └─ Port: 8080 (HTTP alternate)
│  └─ Action: Block at firewall
│
├─ Domain: sofacy-payload.xyz (registered 2025-12-01)
│  └─ WHOIS: Privacy enabled (attacker identity hidden)
│  └─ Action: DNS sinkhole
│
├─ Domain: decoy-vml.org (Decoy VPN infrastructure)
│  └─ Purpose: Anonymize attacker access
│  └─ Action: Monitor for connections
└─ Action: Add to threat intelligence feeds

EMAIL INDICATORS:
├─ Sender domain: government-consultant.xyz
│  └─ Mimics: government.com (legitimate firm)
│  └─ Action: Block domain at email gateway
│
├─ Subject patterns:
│  ├─ "Urgent: Energy policy briefing required"
│  ├─ "Q1 2026 strategic planning document"
│  └─ "Executive meeting minutes - CONFIDENTIAL"
│
└─ Attachment names:
   ├─ "2026_Strategy.docm"
   ├─ "Meeting_Notes_Energy.docx"
   └─ "Q1_Planning.xlsx"
```

---

## Intelligence Report Types

### 1. Threat Actor Profile

```
THREAT ACTOR REPORT: APT28 (Fancy Bear)

Alias: Fancy Bear, Sofacy, STRONTIUM, Pawn Storm, Group 74
Attribution: Russian Military Intelligence (GRU Unit 26165)
Active since: 2007
Sophistication: Very High (military-sponsored)
Geography: Moscow, Russia

MOTIVATIONS:
├─ Strategic intelligence (government, defense, diplomacy)
├─ Political interference (elections, influence operations)
├─ Cyber espionage (technology, intellectual property)
└─ Geopolitical advantage (NATO, energy, infrastructure)

TACTICS & TECHNIQUES:
├─ Spear-phishing (highly targeted, researched targets)
├─ Zero-day exploitation (advanced capabilities)
├─ Custom malware (Sofacy, X-Agent)
├─ Credential theft (domain admin escalation)
├─ Persistence mechanisms (6+ methods)
├─ Lateral movement (SMB exploitation, RDP brute force)
└─ Exfiltration (bulk data theft, 50+ GB typical)

INFRASTRUCTURE:
├─ Decoy VPN services (anonymization)
├─ Compromised servers (for C2)
├─ Bullet-proof hosters (long-term infrastructure)
├─ Domain fast-flux (IP changes hourly)
└─ Global IP addresses (appears to come from different countries)

HISTORICAL CAMPAIGNS:
├─ DNC 2016: Democratic National Committee (2016 election interference)
├─ DCCC 2016: Democratic Congressional Campaign Committee
├─ NATO 2021: NATO member countries
├─ Energy 2025-26: Current (Winter Energy campaign)

RECOMMENDATIONS:
├─ Monitor for: Sofacy malware signatures
├─ Alert on: Spear-phishing emails from researched senders
├─ Baseline: Expect 5-10 email attempts per organization per month
├─ Response: Assume all phishing attempts contain zero-days
└─ Education: Train users on targeted social engineering
```

### 2. Malware Analysis Report

```
MALWARE REPORT: Sofacy Backdoor (Variant 4.2)

Malware name: Sofacy, X-Agent (APT28 nomenclature)
Classification: Remote Access Trojan (RAT)
First seen: 2025-12-15
Variant: 4.2 (updated with evasion techniques)
Detection rate: 42/70 VirusTotal engines
Confidence: 99% APT28 malware

TECHNICAL DETAILS:
├─ File size: 256 KB
├─ Compilation date: 2025-12-15 (recent)
├─ Packing: UPX + custom encryption
├─ Language: C/C++ (custom compiled)
├─ Platform: Windows (x86, x64)

CAPABILITIES:
├─ Remote code execution (execute arbitrary commands)
├─ Credential theft (Windows LSASS, browsers)
├─ File exfiltration (steal files, directories)
├─ Persistence (service + registry + DLL injection)
├─ Lateral movement (SMB propagation)
├─ Keylogging (capture all keystrokes)
├─ Screen capture (screenshot capability)
└─ C2 communication (encrypted HTTPS)

NETWORK BEHAVIOR:
├─ C2 connection: 203.0.113.42:8080
├─ Beaconing: Every 300 seconds (5 minutes)
├─ Jitter: ±10% (anti-detection technique)
├─ Protocol: Custom HTTPS (not standard)
├─ Data size: 512-2048 bytes per beacon
└─ Encryption: AES-256 + RSA hybrid

EVASION TECHNIQUES:
├─ Obfuscation: Code is highly obfuscated
├─ Anti-analysis: Anti-debugger checks
├─ Anti-VM: Virtual machine detection
├─ Anti-sandbox: Cuckoo/Anubis detection
└─ Behavior: Appears as legitimate Windows process

DETECTION:
├─ Signature: Hash-based (MD5, SHA256)
├─ Behavior: Process parent-child analysis (services.exe → malware)
├─ Network: C2 connection monitoring (JA3 fingerprint match)
├─ File system: Modified files in %TEMP%, %APPDATA%
└─ Timeline: Compile time match (2025-12-15)

CONTAINMENT:
├─ Kill process: services.exe malware child
├─ Isolate system: Disconnect from network
├─ Clean: Rebuild system from backup
└─ Monitor: Check for re-infection for 30 days

PAYLOAD ANALYSIS:
├─ Dropped files:
│  ├─ C:\Windows\Temp\svc.exe (main malware)
│  ├─ C:\Windows\Temp\help.dll (C2 communication)
│  └─ C:\ProgramData\Windows\update.exe (persistence)
├─ Registry modifications:
│  ├─ HKLM\System\Services\WUS (malicious service)
│  ├─ HKCU\Run\Windows Security (persistence entry)
│  └─ HKLM\Software\Microsoft\Windows\CurrentVersion
├─ Network connections:
│  ├─ 203.0.113.42:8080 (C2 server)
│  ├─ 198.51.100.55:443 (backup C2)
│  └─ 192.0.2.89:8080 (tertiary C2)
└─ Process injection: Into explorer.exe (evasion)
```

---

## Intelligence Sharing

```
DISSEMINATION:

Internal Distribution:
├─ Security team: Full report + IOCs
├─ Executive leadership: Executive summary
├─ Legal/compliance: Data breach assessment
└─ Board of directors: Risk implications

External Sharing:
├─ CISA (Cybersecurity and Infrastructure Security Agency)
├─ FBI Cyber Division
├─ Industry ISAC (Information Sharing and Analysis Center)
├─ Government sector partners
├─ Critical infrastructure partners
└─ Allied nations (if international incident)

Format:
├─ PDF report (shareable format)
├─ JSON IOCs (machine-readable)
├─ MISP feed (threat intelligence platform)
└─ Encrypted email (for sensitive distribution)

TLP (Traffic Light Protocol):
├─ TLP:AMBER = Internal + government agencies
├─ TLP:GREEN = Internal + industry partners
├─ TLP:WHITE = Public disclosure (after embargo)
└─ TLP:RED = Internal only (do not share)
```

---

## References

- MITRE ATT&CK Framework
- Malware Information Sharing Platform (MISP)
- OpenIOC Framework
- Threat Intelligence Report Standards

---

*Document Maintenance:*
- Update threat actor profiles quarterly
- Archive old campaigns (30+ days)
- Correlate with MITRE ATT&CK techniques
- Share externally (per TLP guidelines)
