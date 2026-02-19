# IOC Enrichment Pipeline - Automated Threat Intelligence

**Last Updated:** 2026-02-18  
**Pipeline Status:** Operational  
**Processed IOCs (Month):** 1,247  

---

## Architecture

```
┌─────────────────┐
│  Raw IOCs       │
│  (CSV/TXT)      │
└────────┬────────┘
         │
    ┌────▼────────────────────┐
    │ Deduplication & Parsing │
    │ - Remove duplicates     │
    │ - Normalize formats     │
    │ - Classify by type      │
    └────┬────────────────────┘
         │
    ┌────▼────────────────────────────┐
    │ External API Enrichment          │
    │ - VirusTotal reputation          │
    │ - URLScan.io analysis            │
    │ - Shodan host details            │
    │ - Abuse.ch feeds                 │
    └────┬────────────────────────────┘
         │
    ┌────▼────────────────────────────┐
    │ Context & Correlation             │
    │ - Campaign association            │
    │ - Threat actor linkage            │
    │ - First/last seen tracking        │
    │ - Confidence scoring              │
    └────┬────────────────────────────┘
         │
    ┌────▼────────────────────────────┐
    │ Deploy to Controls               │
    │ - Firewall blocklists            │
    │ - Proxy URL filters              │
    │ - DNS sinkhole feeds             │
    │ - SIEM correlation rules         │
    └────┬────────────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │  Operational Intel   │
    │  (Actionable feeds)  │
    └──────────────────────┘
```

---

## IOC Types & Enrichment Fields

### IPv4 Addresses (45+ documented)

**Example IOC:** 203.0.113.42  
**Source:** NET-2026-003 investigation

**Enrichment Fields:**
```json
{
  "ioc": "203.0.113.42",
  "type": "ipv4",
  "reputation": "malicious",
  "confidence": "high",
  "last_seen": "2026-02-17T14:23:00Z",
  "first_seen": "2026-01-15T08:15:00Z",
  "days_active": 33,
  "virustotal": {
    "malicious_vendors": 24,
    "suspicious_vendors": 5,
    "total_vendors": 72,
    "reputation_score": -87
  },
  "asn": "AS12345",
  "country": "BG",
  "organization": "Cloud Hosting Provider X",
  "hosting_type": "datacenter",
  "threat_categories": [
    "c2_server",
    "malware_distribution",
    "botnet_command_center"
  ],
  "associated_malware": [
    "cobalt_strike",
    "emotet"
  ],
  "abuse_reports": 127,
  "block_recommendations": [
    "firewall_egress",
    "proxy_gateway",
    "dns_sinkhole"
  ]
}
```

**Detection Rule Generated:**
```spl
index=firewall action=allow dest_ip=203.0.113.42
| stats count by src_ip, src_user, dest_port
| where count > 0
| eval risk_score=count*10
```

### Domains (35+ documented)

**Example:** malicious-domain.com  
**Source:** PHISH-001 investigation

**Enrichment:**
```json
{
  "ioc": "malicious-domain.com",
  "type": "domain",
  "reputation": "malicious",
  "confidence": "high",
  "registration_date": "2026-01-08",
  "expiration_date": "2027-01-08",
  "registrar": "NameCheap",
  "dns_records": {
    "a_records": ["203.0.113.42", "203.0.113.43"],
    "mx_records": ["mail.malicious-domain.com"],
    "ns_records": ["ns1.bulletproof-hosting.ru", "ns2.bulletproof-hosting.ru"]
  },
  "ssl_certificate": {
    "issuer": "Let's Encrypt",
    "issued_date": "2026-01-09",
    "valid_from": "2026-01-09",
    "valid_to": "2026-04-09",
    "subject": "*.malicious-domain.com"
  },
  "virustotal_detections": {
    "malicious": 17,
    "suspicious": 4,
    "undetected": 51
  },
  "urlscan_verdict": "malicious",
  "categories": [
    "phishing",
    "credential_harvesting",
    "malware_distribution"
  ],
  "associated_campaigns": [
    "trickbot_distribution_wave_feb2026"
  ],
  "whois": {
    "registrant": "Privacy Protected",
    "registrant_country": "Unknown",
    "privacy_protection": true
  },
  "passive_dns": {
    "history": 3,
    "first_seen_dns": "2026-01-08",
    "resolution_history": [
      "203.0.113.42 (Jan 8-12)",
      "203.0.113.43 (Jan 13-present)"
    ]
  }
}
```

### File Hashes (SHA256, 28+ documented)

**Example:** a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0  
**Source:** CASE-004 malware triage

**Enrichment:**
```json
{
  "hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0",
  "type": "sha256",
  "malware_name": "Emotet.Botnet",
  "family": "Emotet",
  "malware_type": "trojan",
  "threat_level": "critical",
  "virustotal": {
    "detections": 68,
    "undetected": 4,
    "type_tags": ["trojan", "banking_trojan", "infostealer"]
  },
  "first_submission": "2025-12-20",
  "last_analysis": "2026-02-17",
  "file_details": {
    "filename": "updates.exe",
    "size": 524288,
    "type_description": "PE32 executable",
    "sections": ["text", "data", "reloc"],
    "imports": ["kernel32.dll", "user32.dll", "wininet.dll"],
    "exports": []
  },
  "behavioral_analysis": {
    "registry_modifications": [
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    "file_operations": [
      "C:\\Windows\\Temp\\svc.exe",
      "C:\\Windows\\System32\\drivers\\etc\\hosts"
    ],
    "network_connections": [
      "185.220.101.45:443",
      "185.220.102.8:443"
    ],
    "process_injection": true,
    "privilege_escalation_attempts": true
  },
  "dropper": {
    "type": "phishing_attachment",
    "delivery": "malicious_email",
    "lure": "invoice_payment_request"
  }
}
```

### User Agents (TLS JA3 Fingerprints, 5 documented)

**Example:** JA3 fingerprint 47d3cd...a2b1f  
**Source:** NET-2026-003 C2 analysis

**Enrichment:**
```json
{
  "ja3_fingerprint": "47d3cd...a2b1f",
  "type": "tls_fingerprint",
  "reputation": "malicious",
  "associated_malware": ["Cobalt_Strike"],
  "first_seen": "2025-11-01",
  "last_seen": "2026-02-17",
  "total_observations": 341,
  "beacon_characteristics": {
    "check_in_interval": 60,
    "jitter": "5%",
    "data_per_beacon": "1-2MB",
    "encryption": "AES256"
  },
  "tls_details": {
    "cipher_suites": [
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ],
    "elliptic_curves": ["secp256r1", "secp384r1"],
    "supported_versions": ["TLS1.2", "TLS1.3"]
  },
  "c2_servers": [
    "185.220.101.45",
    "185.220.101.46"
  ],
  "detection_method": "Zeek ssl.log + ja3 analysis"
}
```

---

## Enrichment Data Sources

### VirusTotal API Integration

**Query Frequency:** Per-IOC, cached for 30 days  
**Rate Limit:** 4 requests/minute (free tier)  
**Caching Strategy:** Redis cache, 30-day TTL

**Example API Response:**
```json
{
  "data": {
    "attributes": {
      "last_submission_date": 1708172580,
      "last_dns_records": [
        {
          "type": "A",
          "value": "203.0.113.42"
        }
      ],
      "last_http_response_code": 200,
      "last_http_response_content_sha256": "abc123def456...",
      "last_https_certificate": {
        "issuer": "Let's Encrypt",
        "validity": {
          "not_before": 1673366400,
          "not_after": 1681142400
        }
      },
      "reputation": -87,
      "last_analysis_results": {
        "Avast": {
          "category": "malware",
          "engine_name": "Avast",
          "result": "JS:Malware-gen [Trj]"
        },
        "Alibaba": {
          "category": "harmless",
          "result": null
        }
      },
      "last_analysis_stats": {
        "malicious": 17,
        "suspicious": 4,
        "undetected": 51,
        "harmless": 0
      }
    }
  }
}
```

### URLScan.io Integration

**Purpose:** Full URL analysis and screenshot capture  
**Query:** Domains and URLs  
**Response:** Threat verdict, components, screenshot

**Example Analysis:**
```
URL: https://malicious-domain.com/login
Verdict: MALICIOUS
Threat Classifications:
  - Phishing
  - Credential Harvesting
  - Social Engineering

Components:
  - jQuery (legitimate)
  - Bootstrap (legitimate)
  - Custom script (suspicious, obfuscated)

IP: 203.0.113.42
Country: Bulgaria
ASN: AS12345
SSL Certificate: Self-signed (suspicious for banking site)

Recent History:
  - First seen: 2026-01-08 14:23:45 UTC
  - Last seen: 2026-02-17 09:12:30 UTC
  - 341 scans recorded
```

### Shodan Integration

**Purpose:** Passive host and service enumeration  
**Query:** IP addresses  
**Response:** Services, open ports, banners, technologies

**Example:**
```
IP: 203.0.113.42

Services:
- Port 22 (SSH): OpenSSH 7.4
- Port 80 (HTTP): Apache 2.4.6
- Port 443 (HTTPS): Apache 2.4.6
- Port 8080 (HTTP): Cobalt Strike Team Server
- Port 25 (SMTP): Postfix

DNS: reverse.dns.fails

History: 47 changes in last 90 days
Technologies: Linux, Apache, PHP, OpenSSL
```

### Abuse.ch Feeds

**Malware Hashes:** URLhaus, PhishTank blocklist data  
**C2 Tracking:** URLhaus C2 IP tracker  
**Botnet Tracking:** MalwareBazaar IOCs

---

## Confidence Scoring Algorithm

```python
def calculate_confidence_score(ioc_data):
    """
    Composite confidence score (0-100):
    - High: 75-100 (block immediately)
    - Medium: 50-74 (investigate)
    - Low: 0-49 (monitor only)
    """
    
    score = 0
    
    # VirusTotal detections (max 30 points)
    detection_ratio = ioc_data['vt_detections'] / ioc_data['vt_total_vendors']
    score += min(30, detection_ratio * 40)
    
    # Historical observation count (max 20 points)
    observations = ioc_data['observation_count']
    score += min(20, observations / 100)
    
    # Age of IOC (max 15 points)
    days_active = (date.today() - ioc_data['first_seen']).days
    score += min(15, days_active / 30)
    
    # Campaign association (15 points bonus)
    if ioc_data['associated_campaigns']:
        score += 15
    
    # Threat level (max 20 points)
    threat_levels = {'critical': 20, 'high': 15, 'medium': 10, 'low': 5}
    score += threat_levels.get(ioc_data['threat_level'], 0)
    
    return min(100, score)
```

**Example Scores:**
| IOC | Type | VT Detections | Campaign | Days Active | Score | Recommendation |
|-----|------|---------------|----------|-------------|-------|-----------------|
| 203.0.113.42 | IP | 24/72 | Cobalt Strike | 33 | 92 | Block immediately |
| malicious-domain.com | Domain | 17/72 | Emotet | 40 | 88 | Block immediately |
| a1b2c3d4... | Hash | 68/72 | Emotet | 60 | 85 | Block immediately |
| suspicious-ip.net | IP | 3/72 | Unknown | 5 | 28 | Monitor only |

---

## Deployment to Controls

### Firewall Blocklist
```
# Generated 2026-02-18
# Confidence: High (>75)
# Update Frequency: 6 hours
# Total Entries: 47 IPs, 35 domains

# IPv4 Malicious Hosts
203.0.113.42/32
203.0.113.43/32
185.220.101.45/32
185.220.102.8/32

# Domain Blocklist
malicious-domain.com
phish-site.net
c2-beacon.ru
```

### Proxy/DNS Integration
```
# Squid ACL format
acl blocked_domains dstdomain .malicious-domain.com
acl blocked_domains dstdomain .phish-site.net
http_access deny blocked_domains

# Bind DNS zone file
malicious-domain.com. A 127.0.0.1
phish-site.net. A 127.0.0.1
```

### SIEM Detection Rules (Splunk SPL)

```spl
# Alert on traffic to known C2 servers
index=firewall OR index=proxy dest_ip IN (203.0.113.42, 203.0.113.43, 185.220.101.45)
| stats count by src_ip, src_user, dest_ip, dest_port
| where count > 0
| eval risk_score=count*20
| search risk_score > 50

# Alert on downloads from malicious domains
index=proxy dest_domain="malicious-domain.com" OR dest_domain="phish-site.net"
| where uri_extension IN (exe, dll, zip, pdf)
| stats count by src_ip, src_user, uri
| where count >= 1
```

---

## Metrics & Performance

**Last 30 Days:**
- IOCs Processed: 1,247
- IOCs Blocked: 847
- False Positives: 12 (0.96%)
- Average Enrichment Time: 4.2 seconds
- Cache Hit Rate: 78%
- API Costs (VirusTotal): $12.40/month

**Detection Effectiveness:**
- Known malicious traffic blocked: 347 incidents
- Prevented infections estimated: 12-18
- Cost avoidance: $240,000+ (assuming breach cost)

---

*Pipeline managed by: Threat Intelligence Team*  
*Last review: 2026-02-17*  
*Next review: 2026-03-17*
