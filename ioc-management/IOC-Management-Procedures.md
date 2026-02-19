# IOC (Indicator of Compromise) Management Procedures

**Version:** 1.4  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## IOC Management Overview

IOC management is the systematic collection, validation, enrichment, and distribution of threat indicators across security tools.

---

## IOC Types

```
PRIMARY IOC TYPES:

1. FILE HASHES
   ├─ MD5: 32 hexadecimal characters
   ├─ SHA256: 64 hexadecimal characters (preferred)
   ├─ Purpose: Identify known malware
   └─ Source: VirusTotal, malware databases

2. IP ADDRESSES
   ├─ IPv4: Attacker infrastructure, C2 servers
   ├─ IPv6: Emerging threat infrastructure
   ├─ Format: CIDR notation (e.g., 203.0.113.0/24)
   └─ Source: Firewall logs, incident investigations

3. DOMAIN NAMES
   ├─ Malicious domains (C2, phishing, malware hosting)
   ├─ Typosquatting (company-lookalikes)
   ├─ Format: FQDN (e.g., emotet-c2.xyz)
   └─ Source: DNS logs, threat intelligence feeds

4. URL INDICATORS
   ├─ Full URLs with path (e.g., http://evil.com/malware.exe)
   ├─ Phishing URLs
   ├─ Malware delivery URLs
   └─ Source: Email analysis, incident logs

5. EMAIL INDICATORS
   ├─ Sender email addresses (spoofed)
   ├─ Email subject patterns
   ├─ Attachment names (disguised payloads)
   └─ Source: Email gateway logs

6. NETWORK INDICATORS
   ├─ Ports (suspicious outbound ports)
   ├─ Protocols (unusual traffic patterns)
   ├─ Beaconing intervals (malware calling home)
   └─ Source: IDS/IPS, SIEM logs

7. BEHAVIORAL INDICATORS
   ├─ Process execution patterns (Office → PowerShell)
   ├─ Registry modifications
   ├─ File system activity
   └─ Source: EDR logs, memory forensics

8. THREAT ACTOR INDICATORS
   ├─ Modus operandi (how they attack)
   ├─ TTPs (tactics, techniques, procedures)
   ├─ Group names/aliases
   └─ Source: MITRE ATT&CK, threat reports
```

---

## IOC Workflow

### Step 1: Collection

```
IOC Sources:

Internal Sources:
├─ Incident investigations (IOCs from compromises)
├─ SIEM logs (malicious activity detected)
├─ Firewall logs (C2 connections blocked)
├─ EDR alerts (malware detected)
└─ Email security (phishing detected)

External Sources:
├─ Threat intelligence feeds (VirusTotal, AlienVault)
├─ Law enforcement sharing (FBI, CISA)
├─ Industry groups (ISACs)
├─ Security researchers (public blogs, Twitter)
└─ Vendor advisories (Microsoft, Adobe)

Collection Process:
├─ Automated: Pull feeds daily (scripts/APIs)
├─ Manual: Analyst review of incidents
├─ Rapid: Real-time incident IOC extraction
└─ Retroactive: Hunt historical data for old IOCs
```

### Step 2: Validation

```
Validation Questions:

1. Is this really a malicious IOC?
   ├─ File hash: Does VirusTotal agree? (majority detection)
   ├─ IP: Is it listed in threat intelligence?
   ├─ Domain: Is it registered by attacker (WHOIS)?
   └─ High confidence: Multiple sources agree

2. Could this be a false positive?
   ├─ IP: Could be legitimate ISP or company IP?
   ├─ Domain: Could be misspelled legitimate domain?
   ├─ Hash: Could be old version of legitimate software?
   └─ Verify: Against known good baseline

3. Is this unique and valuable?
   ├─ Is this IOC already known/tracked?
   ├─ Will this aid detection?
   ├─ Can we action on this IOC?
   └─ Too generic: "exe" file extension (not useful)

Validation Examples:

✓ VALID IOC - File Hash:
├─ MD5: d131dd02c5e6eec49b58f6ef5360dd6c
├─ Detection: 45/70 VirusTotal engines agree = MALWARE
├─ Verdict: High confidence, add to blocklist

❌ INVALID IOC - IP Address:
├─ IP: 8.8.8.8 (Google DNS)
├─ Risk: Could be legitimate traffic
├─ Verdict: Too many false positives, skip

✓ VALID IOC - C2 Domain:
├─ Domain: emotet-c2.xyz (registered 2026-02-15)
├─ WHOIS: Privacy-enabled, attacker-registered
├─ DNS: Resolves to known malicious IP
├─ Threat intelligence: Multiple sources confirm C2
└─ Verdict: High confidence, block at DNS
```

### Step 3: Enrichment

```
Enrichment Process:

File Hash Enrichment:
├─ MD5: a1b2c3d4e5f6g7h8
├─ VirusTotal:
│  ├─ Malware name: Emotet banking trojan
│  ├─ Detection rate: 48/70
│  ├─ First submission: 2026-02-15
│  └─ Behavioral tags: Banking trojan, botnet
├─ Threat intelligence tags:
│  ├─ Malware family: Emotet
│  ├─ Attack type: Trojan
│  ├─ Severity: CRITICAL
│  └─ Recommendation: Isolate system, rebuild from backup

IP Address Enrichment:
├─ IP: 203.0.113.42
├─ GEO location: Russia (Moscow)
├─ ASN: AS25 Rostelecom
├─ Host: Compromised server (infrastructure type)
├─ DNS reverse: [no reverse DNS - anonymous]
├─ Threat intelligence:
│  ├─ Listed in: AbuseIPDB, Shodan
│  ├─ Threat type: C2 server
│  ├─ Associated malware: Emotet
│  └─ Last seen: 2026-02-18 23:45 UTC

Domain Enrichment:
├─ Domain: emotet-c2.xyz
├─ Registrar: GoDaddy (privacy enabled)
├─ DNS provider: Cloudflare
├─ Registration date: 2026-02-15
├─ Expiration: 2027-02-15
├─ Associated IPs:
│  ├─ 203.0.113.42 (Russia)
│  ├─ 198.51.100.55 (Ukraine)
│  └─ Fast-flux: IP changes hourly (evasion)
├─ Threat intel:
│  ├─ C2 domain (Emotet)
│  ├─ High confidence
│  └─ Recommend blocking at DNS/firewall
```

### Step 4: Distribution

```
Distribution Targets:

1. Antivirus/EDR Systems:
   ├─ File hashes → Signature update
   ├─ Malware family names → Detection rules
   └─ Distribution: Push to all endpoints within 1 hour

2. Firewall/Network:
   ├─ IP addresses → Blocklist
   ├─ Domains → DNS blocklist
   ├─ Ports → Port-based rules
   └─ Distribution: Update within 5 minutes (critical)

3. SIEM:
   ├─ IOCs → Correlation rules
   ├─ Domains → URL filtering rules
   ├─ IPs → Connection monitoring rules
   └─ Distribution: Real-time (API integration)

4. DNS/Proxy:
   ├─ Domains → DNS blocklist (sinkhole)
   ├─ URLs → Web filter blocklist
   └─ Distribution: Within 15 minutes

5. Email Gateway:
   ├─ Sender addresses → Blocklist
   ├─ Domains → Sender domain blocklist
   ├─ Attachment hashes → Quarantine rules
   └─ Distribution: Within 30 minutes

Example Distribution Process:

New IOC: Emotet C2 domain (emotet-c2.xyz)
├─ Extract domain: emotet-c2.xyz
├─ Map to tools:
│  ├─ Firewall: Add to IP blocklist (resolved IP)
│  ├─ DNS: Add to sinkhole
│  ├─ Proxy: Add to URL blocklist
│  ├─ SIEM: Create alert rule
│  └─ Email: Add to sender blocklist
├─ Automated via API: <5 minutes
└─ Manual verification: Confirm in all tools
```

### Step 5: Monitoring & Tuning

```
Monitoring Questions:

1. Is the IOC still active?
   ├─ Is C2 server still responding?
   ├─ Is malware still being distributed?
   ├─ Are attackers still using this infrastructure?
   └─ Update: Remove old IOCs after 90 days (if inactive)

2. Is the IOC effective?
   ├─ How many blocks has this IOC generated?
   ├─ Has it prevented any incidents?
   ├─ Are there false positives?
   └─ Tune: Adjust rules if too many false positives

3. Is the IOC source reliable?
   ├─ What's the accuracy rate of this source?
   ├─ Have they had false positives before?
   ├─ Do other sources confirm this IOC?
   └─ Trust: Only use reliable sources

Example IOC Metrics:

IOC: 203.0.113.42 (C2 IP)
├─ Added: 2026-02-15
├─ Status: ACTIVE
├─ Blocks: 234 connections attempted (blocked)
├─ False positives: 0
├─ Effectiveness: 100% (all were malicious)
├─ Still active: YES (latest sighting 2026-02-19)
└─ Recommendation: Keep in blocklist
```

---

## IOC Database Structure

```
Recommended IOC Database Fields:

IOC_ID:           Unique identifier
IOC_TYPE:         Hash/IP/Domain/URL/etc.
IOC_VALUE:        The actual indicator (e.g., 203.0.113.42)
MALWARE_FAMILY:   Emotet, Trickbot, etc. (if malware)
ATTACK_TYPE:      C2, Phishing, Malware, etc.
SEVERITY:         CRITICAL/HIGH/MEDIUM/LOW
CONFIDENCE:       Percentage confidence (0-100%)
SOURCE:           Where did it come from?
ADDED_DATE:       When was it added to DB?
LAST_SEEN:        Last detection timestamp
EXPIRATION_DATE:  When to remove (if applicable)
STATUS:           ACTIVE/INACTIVE/DEPRECATED
NOTES:            Additional context
DISTRIBUTION:     Which tools received this IOC?
BLOCKS_COUNT:     How many times this IOC was triggered?

Example Record:

IOC_ID:           IOC_2026_00234
IOC_TYPE:         Domain
IOC_VALUE:        emotet-c2.xyz
MALWARE_FAMILY:   Emotet
ATTACK_TYPE:      C2
SEVERITY:         CRITICAL
CONFIDENCE:       95%
SOURCE:           VirusTotal (community detection)
ADDED_DATE:       2026-02-15 14:30 UTC
LAST_SEEN:        2026-02-19 15:45 UTC
EXPIRATION_DATE:  2026-05-19 (90 days)
STATUS:           ACTIVE
NOTES:            "Fast-flux C2, IP changes hourly"
DISTRIBUTION:     Firewall, DNS, SIEM
BLOCKS_COUNT:     156
```

---

## IOC Lifecycle

```
IOC Lifecycle Timeline:

Discovery (Day 0):
├─ IOC identified (incident or threat feed)
├─ Added to database
└─ Distributed to all tools

Active Use (Days 1-30):
├─ Being actively blocked/detected
├─ Monitoring for false positives
├─ Updating based on new sightings
└─ Contributing to threat intelligence

Maturation (Days 31-90):
├─ Still active but older threat
├─ May have less relevance
├─ Continued monitoring
└─ Prepare for deprecation

Retirement (Day 90+):
├─ If no recent sightings: Mark INACTIVE
├─ Remove from critical tools (firewall, AV)
├─ Keep in database for historical reference
├─ Reactivate if seen again
└─ Archive to cold storage (if needed)

Example Timeline for C2 Domain:

Day 0 (Feb 15):     emotet-c2.xyz detected → Add to database
Day 1 (Feb 16):     23 connections blocked → Active
Day 5 (Feb 20):     47 total blocks → Effective
Day 30 (Mar 16):    89 total blocks → Steady
Day 60 (Apr 15):    98 total blocks → Minimal new
Day 90 (May 15):    Last sighting: Apr 12 → Mark INACTIVE
Day 91 (May 16):    Remove from firewall blocklist
Day 180 (Aug 13):   Archive to cold storage (historical)
```

---

## References

- MISP (Malware Information Sharing Platform)
- OpenIOC Framework
- STIX/TAXII Standards
- AlienVault OTX

---

*Document Maintenance:*
- Review IOC database monthly
- Retire old IOCs (90-day lifecycle)
- Monitor effectiveness metrics
- Update procedures as threats evolve
