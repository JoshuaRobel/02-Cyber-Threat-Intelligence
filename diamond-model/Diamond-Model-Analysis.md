# Diamond Model of Intrusion Analysis

**Version:** 1.5  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Overview

The Diamond Model is a framework for analyzing intrusions by examining four key elements: **Adversary, Infrastructure, Capability, and Victim**. Understanding these elements helps defenders establish TTPs (Tactics, Techniques, Procedures) and create effective detection strategies.

---

## The Four Vertices of the Diamond

```
                    ADVERSARY
                       │
                       │
INFRASTRUCTURE ────────────────── CAPABILITY
                       │
                       │
                      VICTIM
```

### Vertex 1: ADVERSARY

**Definition:** The actor or group conducting the attack

**Characteristics:**
- Operator (individual conducting the attack)
- Customer (who benefits from the attack - may be different)
- Organization (larger structure, e.g., APT nation-state)

**Real-World Example - APT28 (Fancy Bear):**

```
OPERATOR:
├─ Individuals from Russian military GRU
├─ Training level: Military-grade
├─ Experience: 10+ years
└─ Sophistication: High

CUSTOMER:
├─ Russian Federation (state)
├─ Objective: Espionage (political intelligence)
└─ Benefit: Strategic advantage in geopolitics

ORGANIZATION:
├─ GRU Unit 26165
├─ Size: 100+ operators
├─ Budget: Unlimited (state-funded)
└─ Infrastructure: Dedicated state resources
```

**Adversary Profiling for Detection:**

```
Question: Is this APT28 or a different group?

Indicators of APT28:
├─ Infrastructure: Decoy VPN services (SOCKS5)
├─ Malware: Sofacy/X-Agent (custom backdoor)
├─ Tactics: Spear phishing (highly targeted)
├─ Timing: Office hours (Moscow timezone)
├─ Targeting: Political figures, defense contractors
└─ Historical: Consistent over 10+ years

Indicators of Different Group:
├─ Malware: WellMess, Zebrocy (APT29 signatures)
├─ Timing: Random (different timezone)
├─ Targeting: Financial systems (APT10 pattern)
└─ Infrastructure: Commercial hosting (less sophisticated)

Detection Rule:
IF malware_hash="Sofacy" AND timing=Moscow_hours AND targeting=political
THEN likely_APT28
ELSE investigate_further
```

### Vertex 2: INFRASTRUCTURE

**Definition:** Physical and logical systems used by the adversary

**Components:**

```
┌─────────────────────────────────────────────┐
│         ADVERSARY INFRASTRUCTURE             │
├─────────────────────────────────────────────┤
│ Type 1: Control Infrastructure               │
│  └─ Systems controlled by adversary:         │
│     ├─ Command & Control (C2) servers       │
│     ├─ Reverse proxy servers (hide origin)  │
│     ├─ DNS servers (malicious redirects)    │
│     └─ VPN services (anonymize access)      │
├─────────────────────────────────────────────┤
│ Type 2: Staging Infrastructure               │
│  └─ Systems for preparation/staging:        │
│     ├─ Compromised servers (hosting malware │
│     ├─ Download servers (delivering payloads │
│     ├─ Testing/development environments     │
│     └─ Reconnaissance staging points        │
├─────────────────────────────────────────────┤
│ Type 3: Support Infrastructure               │
│  └─ Services used operationally:            │
│     ├─ Hosting providers (rent servers)     │
│     ├─ Domain registrars (register domains) │
│     ├─ VPN services (anonymity)             │
│     ├─ Bulletproof hosting (criminal-friendly)
│     └─ Cryptocurrency exchangers (payment)  │
└─────────────────────────────────────────────┘
```

**Infrastructure Analysis Example - Emotet Botnet:**

```
CONTROL INFRASTRUCTURE:

Primary C2 Servers:
├─ 203.0.113.42 (compromised server in Bulgaria)
├─ 198.51.100.55 (compromised server in Czech Republic)
├─ 192.0.2.89 (Amazon EC2 instance, rented)
└─ All contacted via HTTPS (port 443)

Pattern:
├─ Server hosting provider changes every 2-3 months
├─ New servers added as old ones blocked
├─ Dual-use infrastructure (legitimate hosting abused)
└─ Average server lifetime before takedown: 90 days

DNS INFRASTRUCTURE:
├─ Malicious domains: emotet-pay.xyz, emotet-control.top
├─ Domain registrar: GoDaddy (legitimate, privacy-enabled)
├─ DNS provider: Cloudflare (legitimate, free tier)
├─ Purpose: Redirect traffic to current C2 servers
└─ Detection: Domain reputation scoring

STAGING INFRASTRUCTURE:
├─ Compromised WordPress sites (hosting malware)
├─ File upload services (staging malware)
├─ GitHub repositories (hosting malware source code)
└─ Purpose: Distribute malware to target networks

SUPPORT INFRASTRUCTURE:
├─ Bulletproof hosting providers
├─ VPN services (NordVPN, Expressway abused)
├─ Cryptocurrency exchanges (payment for services)
└─ Dark web forums (recruit new operators)
```

**Infrastructure Detection:**

```
DETECTION QUERY 1: Find C2 Infrastructure

Zeek DNS Log Analysis:
query: emotet-pay.xyz
answers: 203.0.113.42 (MALICIOUS)
timestamp: 2026-02-15 09:30:45
client: 10.0.20.33 (infected workstation)

Action:
├─ Alert: Domain contacted by internal system
├─ Block: Add 203.0.113.42 to firewall blocklist
├─ Isolate: Workstation 10.0.20.33 removed from network
└─ Investigate: How many other internal systems contacted this?

DETECTION QUERY 2: Find Compromised Staging Servers

Reverse DNS Lookup: 203.0.113.42
Result: server.legitcompany-hosting.com
Historical: Server was clean 6 months ago
Current: Hosting malware payload
Analysis: Server has been compromised (possibly earlier attack)

Action:
├─ Notify: Hosting provider of compromised server
├─ Block: All traffic from 203.0.113.42
├─ Research: Who compromised this server? (unrelated incident?)
└─ Hunt: Has this server been used to attack us before?
```

### Vertex 3: CAPABILITY

**Definition:** Tools and techniques used in the attack

**Capability Spectrum:**

```
CUSTOM MALWARE (High Sophistication):
├─ Sofacy backdoor (APT28 custom)
├─ Capabilities: Remote code execution, lateral movement
├─ Detection: Signature-based (known malware hash)
└─ Timeline: Operational for 10+ years

PUBLICLY AVAILABLE TOOLS (Medium Sophistication):
├─ Metasploit framework
├─ Cobalt Strike beacon
├─ Empire PowerShell framework
├─ Capabilities: Post-exploitation, lateral movement
└─ Detection: Behavioral analysis + signature detection

LIVING OFF THE LAND (Low Detection):
├─ PowerShell (built-in Windows)
├─ cmd.exe (command shell)
├─ WMI (Windows Management Instrumentation)
├─ Capabilities: System enumeration, execution
└─ Detection: Process parent-child analysis + command-line inspection

LEGITIMATE TOOLS ABUSED:
├─ PsExec (remote command execution)
├─ RDP (remote desktop)
├─ SSH (secure shell)
├─ Capabilities: Admin access, remote control
└─ Detection: Anomalous usage patterns (off-hours, wrong user)
```

**Capability Analysis - Emotet Malware:**

```
EMOTET CAPABILITIES:

Delivery:
├─ Trojanized attachments (Word documents)
├─ Malicious links (redirect to malware)
└─ Exploit kits (Zero-day exploitation)

Installation:
├─ Writes to C:\Users\*\AppData\Roaming\emotet.exe
├─ Creates persistence:
│  ├─ Services: "Windows Update Service"
│  ├─ Scheduled task: "Windows Maintenance"
│  └─ Registry Run key: HKCU\...\Run\Windows Security
└─ Evasion: Sideloading DLL to bypass UAC

Command & Control:
├─ HTTPS communication (port 443)
├─ Custom encryption (AES + RSA hybrid)
├─ Beaconing frequency: Every 60 seconds ± jitter
└─ C2 domains: Maliciously registered + DNS-fast-flux

Capabilities Granted by C2:
├─ Download additional malware
├─ Harvest banking credentials
├─ Capture email (spam sending)
├─ Lateral movement (propagate to file shares)
└─ Ransomware distribution (Ryuk payload)

Detection Strategy:
├─ Signature: Hash of emotet.exe
├─ Behavioral: Process injection to explorer.exe
├─ Network: HTTPS outbound on unusual schedule
├─ Persistence: Scheduled task creation alerts
└─ Timeline: Disable C2, perform forensics, rebuild system
```

### Vertex 4: VICTIM

**Definition:** The target of the attack

**Victim Characteristics:**

```
PROFILE 1: Large Enterprise Target
├─ Organization: Fortune 500 company
├─ Employees: 10,000+
├─ Industry: Financial services (high-value data)
├─ Security: Mature (SIEM, EDR, IPS deployed)
├─ Attack complexity: High (many defensive layers)
├─ Reward: $millions in stolen data
├─ Typical attacker: APT (nation-state)
└─ Typical objective: Espionage, IP theft

PROFILE 2: Small Business Target
├─ Organization: Local accounting firm
├─ Employees: 20
├─ Industry: Professional services
├─ Security: Minimal (basic firewall only)
├─ Attack complexity: Low (easy access)
├─ Reward: $10-100K in ransomware payment
├─ Typical attacker: Ransomware-as-a-service (RaaS)
└─ Typical objective: Financial extortion

PROFILE 3: Government Agency Target
├─ Organization: Federal agency
├─ Employees: 500-5000
├─ Security: High (classified networks, air-gapped)
├─ Attack complexity: Very high (deliberate targeting)
├─ Reward: Sensitive government documents
├─ Typical attacker: Competitor nation-state
└─ Typical objective: Strategic intelligence
```

**Victim Identification & Selection:**

```
Why did attacker choose THIS victim?

Analysis Framework:
1. Value Assessment:
   ├─ Data value: Customer PII, health records, financial data
   ├─ Intellectual property: Patents, research, source code
   ├─ Operational value: Disruption impact (hospitals vs gaming sites)
   └─ Strategic value: Government, competitor, critical infrastructure

2. Vulnerability Assessment:
   ├─ Known vulnerabilities: Unpatched systems
   ├─ Weak security controls: Poor access controls
   ├─ Supply chain: Weak 3rd party vendor
   └─ Human factor: Employee susceptible to phishing

3. Accessibility Assessment:
   ├─ Network reachability: Public-facing systems
   ├─ Geographic proximity: Local network access possible
   ├─ Timing: Business hours vs after-hours
   └─ Defenses: Known vs unknown security controls

EXAMPLE: Why was this company targeted for ransomware?

Analysis:
├─ Value: Hospitals = high (ransomware payment likely)
├─ Vulnerability: Unpatched RDP (public-facing)
├─ Accessibility: RDP port exposed to internet
├─ Known weak: Hospital IT staff less sophisticated
├─ Potential revenue: $200K+ ransom payment
└─ Conclusion: Low-hanging fruit for ransomware gang

Detection Strategy:
├─ Scan for other hospitals with exposed RDP
├─ Proactively reach out to vulnerable organizations
├─ Provide remediation guidance (free defense)
└─ Build goodwill, establish threat intelligence sharing
```

---

## Using the Diamond Model for Detection

### Example: Emotet Campaign Against Finance Sector

```
DIAMOND ANALYSIS:

ADVERSARY: Emotet gang (Eastern European, initially)
├─ Operator: TA542 group (criminal cartel)
├─ Customer: Various (botnet sold to highest bidder)
├─ Organization: 50-100 criminal operators
└─ Motivation: Financial profit ($millions/year)

INFRASTRUCTURE: Complex, fast-changing
├─ C2 servers: 50-200 active at any time
├─ Domains: 100-500 malicious domains
├─ Hosting: Multiple countries (bulletproof hosting)
├─ Fast-flux: IP changes every 30-60 minutes
└─ Botnet size: 1.5-3 million infected systems

CAPABILITY: Advanced malware platform
├─ Delivery: Macro-enabled Office, exploit kits
├─ Installation: 5-8 persistence mechanisms
├─ Capabilities: Banking trojan + botnet + loader
├─ Tools: Custom malware (proprietary)
└─ C2 protocol: HTTPS with custom encryption

VICTIM: Financial institutions
├─ Primary target: Banks, payment processors
├─ Secondary target: Their customers
├─ Attack vector: Email phishing (convincing lures)
├─ Data value: Banking credentials, wire transfers
└─ Financial impact: $millions in fraud

DETECTION APPROACH:

By Adversary:
├─ Know APT characteristics (timing, methods)
├─ Identify operator behavior (patterns)
├─ Build adversary profile (historical TTPs)
└─ Action: Recognize when THIS adversary attacks

By Infrastructure:
├─ Monitor for known C2 domains (threat intel feeds)
├─ Detect new C2 infrastructure (network behavioral anomalies)
├─ Track domain registrations (new malicious domains)
└─ Action: Block C2 before it reaches internal systems

By Capability:
├─ Detect malware signatures (antivirus definitions)
├─ Identify exploitation attempts (IDS/IPS rules)
├─ Recognize attack patterns (process execution)
└─ Action: Prevent initial compromise

By Victim:
├─ Identify targeted organizations (phishing email recipients)
├─ Assess victim vulnerability (unpatched systems)
├─ Monitor for successful infection (behavioral signals)
└─ Action: Notify and assist with remediation

INTEGRATED DETECTION:

Rule: IF (origin=known_emotet_C2 OR domain=emotet_malicious) 
       AND (victim_industry=financial) 
       AND (capability=macro_infection) 
       THEN high_confidence_emotet_attack
       ACTION: immediate_isolation + incident_response
```

---

## Adversary Behaviors & Attribution

### Adversary Repeatability (APT Behavior Patterns)

```
Observation: Adversaries typically have consistent behaviors

APT28 Characteristics (Consistent over 10 years):
├─ Infrastructure: Rents Decoy VPN infrastructure
├─ Timing: Operates during Moscow business hours
├─ Targeting: Political/defense contractors
├─ Malware: Uses Sofacy/X-Agent exclusively
├─ Methodology: Highly targeted spear phishing
├─ Sophistication: High

Detection Value:
├─ When we see Sofacy malware → likely APT28
├─ When operation is off-hours → likely not APT28
├─ When targeting is random companies → likely not APT28
└─ Combine indicators → high confidence attribution

APT1 (Chinese PLA Unit 61398) Characteristics:
├─ Infrastructure: Dedicated state resources
├─ Timing: Shifts between timezones (large team)
├─ Targeting: Intellectual property theft (industry-wide)
├─ Malware: Uses Poison Ivy RAT consistently
├─ Data exfiltration: Large volumes (gigabytes)
├─ Sophistication: Very high

Detection Value:
├─ Large volume data transfers → possible APT1
├─ Intellectual property theft → likely APT1
├─ Poison Ivy malware → likely APT1
└─ Combine indicators → attribution possible
```

---

## References

- Diamond Model: Intrusion Analysis for Intelligence
- MITRE ATT&CK Framework (complements Diamond Model)
- Adversary TTP documentation

---

*Version History:*
- v1.5 (2026-02-19): Added real-world examples and detection queries
- v1.4 (2026-01-15): Expanded infrastructure analysis
- v1.3 (2025-12-01): Added victim profiling
- v1.0 (2025-10-15): Initial framework