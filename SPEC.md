# Cyber Intelligence Gateway (CIG) - Specification

## Project Overview
- **Project Name**: Cyber Intelligence Gateway (CIG)
- **Type**: Network Security Monitoring & Threat Intelligence Platform
- **Core Functionality**: Real-time correlation of MISP threat feeds and pfBlockerNG DNS blocklists with local network traffic (LAN/WAN), capturing PCAP and logging events
- **Target Users**: Security analysts, SOC teams, network administrators

## Architecture

### Components
```
┌─────────────────────────────────────────────────────────────────┐
│                    Cyber Intelligence Gateway                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   MISP API   │  │ pfBlockerNG  │  │  Network Interfaces  │  │
│  │   (Feeds)    │  │   (Feeds)    │  │  (LAN/WAN Capture)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                     │              │
│         ▼                 ▼                     ▼              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Threat Intelligence Engine                  │  │
│  │  • IOC Extraction (IPs, Domains, Hashes, URLs)           │  │
│  │  • Feed Normalization & Deduplication                     │  │
│  │  • Real-time Blocklist Updates                            │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │                                    │
│                            ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Traffic Analyzer & Matcher                  │  │
│  │  • PCAP Capture (tcpdump/libpcap)                        │  │
│  │  • DNS Query Logging                                      │  │
│  │  • NetFlow/PCAP Analysis                                  │  │
│  │  • Real-time Threat Matching                             │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │                                    │
│                            ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Event Logger & Storage                      │  │
│  │  • SQLite/PostgreSQL Database                            │  │
│  │  • EveJSON Log Storage                                   │  │
│  │  • PCAP File Archive                                     │  │
│  │  • Alert Dashboard API                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack
- **Language**: Python 3.11+
- **Database**: SQLite (embedded), PostgreSQL (production)
- **PCAP**: libpcap, python-libpcap
- **MISP**: pymisp library
- **Networking**: scapy, dnspython
- **API**: FastAPI
- **Container**: Docker, Docker Compose

## Functionality Specification

### 1. MISP Feed Integration
- Connect to MISP servers via API
- Fetch threat indicators (IOCs):
  - IP addresses (IPv4/IPv6)
  - Domains
  - File hashes (MD5, SHA1, SHA256)
  - URLs
  - Email patterns
- Support multiple MISP instances
- Configurable feed update intervals
- Automatic IOC extraction and normalization

### 2. pfBlockerNG Feed Integration
- Fetch DNS blocklists from pfSense/pfBlockerNG
- Support formats:
  - Plain text (one domain/IP per line)
  - GeoIP country blocks
  - ASnum blocks
- Merge and deduplicate blocklists
- Real-time DNS query matching

### 3. Network Traffic Capture
- **LAN Monitoring**: Capture on internal network interfaces
- **WAN Monitoring**: Capture on external/ISP-facing interfaces
- PCAP file generation with:
  - Timestamp
  - Source/Destination IP
  - Port numbers
  - Protocol information
  - Payload snippets (configurable)
- Ring buffer for continuous capture
- PCAP file rotation and archiving

### 4. Event Logging
- **Log Sources**:
  - Suricata/EveJSON format
  - DNS query logs
  - PCAP metadata
  - Alert events
- **Storage**:
  - Structured database (SQLite)
  - JSON log files
  - PCAP archives
- **Retention**: Configurable (default 30 days)

### 5. Threat Matching Engine
- Real-time DNS query matching against blocklists
- PCAP packet inspection for IOCs
- Alert generation with:
  - Severity levels (Critical, High, Medium, Low, Info)
  - Timestamp
  - Source IP
  - Indicator type
  - Matching feed source
- Webhook/notification support

## Configuration

### Environment Variables
```
# MISP Configuration
MISP_URL=https://misp.example.com
MISP_API_KEY=your-api-key
MISP_VERIFY_SSL=false

# pfBlocker Configuration
PFBLOCKER_URL=http://pfsense:443
PFBLOCKER_FEEDS=https://raw.githubusercontent.com/pfBlockerNG/devel/master/etc/rc.d/aliasloader

# Network Configuration
LAN_INTERFACE=eth0
WAN_INTERFACE=eth1
PCAP_DIR=/data/pcaps
PCAP_ROTATION_SIZE=100M

# Database
DATABASE_PATH=/data/cig.db

# API Server
API_HOST=0.0.0.0
API_PORT=8000
```

## Data Models

### Alert
```python
{
    "id": "uuid",
    "timestamp": "ISO8601",
    "severity": "critical|high|medium|low|info",
    "source_ip": "192.168.1.100",
    "destination_ip": "185.234.219.10",
    "indicator": "evil-domain.com",
    "indicator_type": "domain|ip|hash|url",
    "feed_source": "misp|pfblocker",
    "rule_id": "MISP:12345",
    "raw_log": {}
}
```

### PCAP Metadata
```python
{
    "id": "uuid",
    "filename": "capture_20240315_143022.pcap",
    "start_time": "ISO8601",
    "end_time": "ISO8601",
    "size_bytes": 104857600,
    "packets_count": 15420,
    "interface": "eth0",
    "alerts_count": 5
}
```

## API Endpoints

### Alerts
- `GET /api/alerts` - List alerts (paginated)
- `GET /api/alerts/{id}` - Get alert details
- `GET /api/alerts/stats` - Alert statistics

### PCAP
- `GET /api/pcaps` - List PCAP files
- `GET /api/pcaps/{id}/download` - Download PCAP
- `GET /api/pcaps/{id}/alerts` - Alerts from PCAP

### Intelligence
- `GET /api/intel/misp` - MISP feed status
- `GET /api/intel/pfblocker` - pfBlocker feed status
- `GET /api/intel/indicators` - Active indicators

### System
- `GET /api/health` - Health check
- `GET /api/stats` - System statistics

## Acceptance Criteria

1. ✅ Application starts successfully in Docker
2. ✅ Connects to MISP server and fetches indicators
3. ✅ Parses pfBlockerNG blocklists
4. ✅ Captures PCAP on configured interfaces
5. ✅ Matches DNS queries against blocklists in real-time
6. ✅ Stores alerts in database
7. ✅ Provides REST API for alerts and PCAP
8. ✅ Gracefully handles network failures
9. ✅ Configurable via environment variables
10. ✅ Proper logging and error handling
