# Cyber Threat Intelligence

Indicator of Compromise (IOC) management, threat actor tracking, and intelligence-driven security operations.

## Contents

### IOC Management
Structured repository of extracted indicators with context, confidence scoring, and expiration tracking.

**IOC Categories:**
| Type | Count | Source |
|------|-------|--------|
| IPv4 Addresses | 45+ | Network investigations |
| Domains | 35+ | Phishing analysis |
| File Hashes (SHA256) | 28+ | Malware triage |
| User Agents | 12+ | C2 detection |
| JA3 Fingerprints | 5 | TLS analysis |

**Enrichment Data:**
- VirusTotal reputation scores
- First/last seen timestamps
- Associated campaigns
- Confidence ratings (High/Medium/Low)
- Block/alert recommendations

### Threat Feeds
Curated IOC lists formatted for direct integration with security tools.

**Available Feeds:**
- `blocklist-ips.txt` — High-confidence malicious IPs
- `blocklist-domains.txt` — Phishing and malware domains
- ` suspicious-ja3.txt` — C2 JA3 fingerprints
- `watchlist-hashes.txt` — Malware file hashes

### Diamond Model of Intrusion Analysis
Applied to major investigations to understand adversary capability and intent.

**Model Applications:**
- Adversary: Threat actor attribution and profiling
- Capability: Tools and TTPs observed
- Infrastructure: C2 servers, domains, IPs
- Victim: Targeting patterns and victimology

### Intelligence Reports
Structured threat intelligence reports following STIX/TAXII principles.

**Report Types:**
- Campaign analysis (e.g., TrickBot distribution wave)
- Threat actor profile summaries
- Emerging threat advisories
- Weekly intelligence summaries

## Enrichment Pipeline

Automated IOC enrichment workflow:

```
Raw IOC → VirusTotal API → Reputation Score → Context Enrichment → Structured Output
   ↓              ↓                  ↓                  ↓                  ↓
Manual      Automated          Risk Rating      Campaign Link      Actionable Intel
Extraction    Lookup           Calculation       Attribution        Feed Generation
```

**Tools Used:**
- VirusTotal API (reputation checking)
- URLScan.io (URL analysis)
- Abuse.ch (threat feeds)
- GreyNoise (internet noise reduction)

## IOC Lifecycle

1. **Extraction** — Manual extraction from investigations
2. **Enrichment** — Automated reputation and context gathering
3. **Validation** — Human review for false positives
4. **Deployment** — Push to blocking tools (firewall, proxy, DNS)
5. **Monitoring** — Track hits and tune confidence
6. **Expiration** — Retire stale IOCs (typically 90 days)

---

*Intelligence without action is just information. Every IOC here has been deployed to production controls or fed into detection rules.*
