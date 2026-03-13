"""
FastAPI Routes for Cyber Intelligence Gateway
"""

import os
import logging
from typing import Optional, List
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.models.database import Database, Alert, PcapFile, Indicator
from app.matching.engine import ThreatMatcher
from app.core.config import settings

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Cyber Intelligence Gateway API",
    description="Threat intelligence and network monitoring API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances (will be initialized in main.py)
_db: Optional[Database] = None
_threat_matcher: Optional[ThreatMatcher] = None


def get_db() -> Database:
    """Get database instance"""
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not initialized")
    return _db


def get_threat_matcher() -> ThreatMatcher:
    """Get threat matcher instance"""
    if _threat_matcher is None:
        raise HTTPException(status_code=503, detail="System not initialized")
    return _threat_matcher


def init_app(database: Database, matcher: ThreatMatcher):
    """Initialize global instances"""
    global _db, _threat_matcher
    _db = database
    _threat_matcher = matcher


# --- Pydantic Models ---

class AlertResponse(BaseModel):
    id: str
    timestamp: str
    severity: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    indicator: str
    indicator_type: str
    feed_source: str
    rule_id: str
    message: str

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertResponse]


class PcapResponse(BaseModel):
    id: str
    filename: str
    filepath: str
    start_time: str
    end_time: str
    size_bytes: int
    packets_count: int
    interface: str
    alerts_count: int

    class Config:
        from_attributes = True


class IndicatorResponse(BaseModel):
    id: str
    value: str
    type: str
    source: str
    feed_id: str
    first_seen: str
    last_seen: str
    tags: str
    count: int

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    alerts: dict
    indicators: dict
    feeds: dict
    captures: List[dict]


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


class DomainCheckRequest(BaseModel):
    domain: str


class DomainCheckResponse(BaseModel):
    domain: str
    matched: bool
    indicator: Optional[dict] = None


# --- Health Endpoints ---

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat()
    )


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get system statistics"""
    database = get_db()
    matcher = get_threat_matcher()

    return StatsResponse(
        alerts=database.get_alert_stats(),
        indicators=database.get_indicator_counts(),
        feeds={
            "misp": matcher.misp_feed.get_status(),
            "pfblocker": matcher.pfblocker_feed.get_status()
        },
        captures=matcher.pcap_capture.get_active_captures()
    )


# --- Alert Endpoints ---

@app.get("/api/alerts", response_model=AlertListResponse)
async def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    indicator_type: Optional[str] = Query(None)
):
    """Get alerts with optional filtering"""
    database = get_db()

    alerts = database.get_alerts(limit=limit, offset=offset, severity=severity, indicator_type=indicator_type)
    stats = database.get_alert_stats()

    return AlertListResponse(
        total=stats["total"],
        alerts=[AlertResponse(**a.to_dict()) for a in alerts]
    )


@app.get("/api/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    """Get a specific alert"""
    database = get_db()

    alert = database.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return AlertResponse(**alert.to_dict())


@app.get("/api/alerts/stats")
async def get_alert_stats():
    """Get alert statistics"""
    database = get_db()
    return database.get_alert_stats()


# --- PCAP Endpoints ---

@app.get("/api/pcaps")
async def get_pcaps(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Get PCAP file list"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    pcaps = db.get_pcaps(limit=limit, offset=offset)
    return {
        "pcaps": [PcapResponse(**p.to_dict()).dict() for p in pcaps]
    }


@app.get("/api/pcaps/{pcap_id}/download")
async def download_pcap(pcap_id: str):
    """Download a PCAP file"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    conn = db.db_path
    import sqlite3
    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT filepath, filename FROM pcap_files WHERE id = ?", (pcap_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="PCAP not found")

    filepath, filename = row
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="PCAP file not found")

    # Check for .gz extension (rotated/compressed files)
    gz_filepath = filepath + ".gz"
    if os.path.exists(gz_filepath):
        filepath = gz_filepath

    with open(filepath, "rb") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/pcaps/{pcap_id}/alerts")
async def get_pcap_alerts(pcap_id: str):
    """Get alerts associated with a PCAP file"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    # Get alerts that might be related to this PCAP (by timestamp)
    # This is a simplified implementation
    conn = db.db_path
    import sqlite3
    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT start_time FROM pcap_files WHERE id = ?
    """, (pcap_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="PCAP not found")

    return {"alerts": []}


# --- Intelligence Endpoints ---

@app.get("/api/intel/misp")
async def get_misp_status():
    """Get MISP feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.misp_feed.get_status()


@app.get("/api/intel/pfblocker")
async def get_pfblocker_status():
    """Get pfBlocker feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.pfblocker_feed.get_status()


@app.get("/api/intel/indicators")
async def get_indicators(
    limit: int = Query(1000, ge=1, le=10000),
    indicator_type: Optional[str] = Query(None)
):
    """Get threat indicators"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    indicators = db.get_indicators(limit=limit, indicator_type=indicator_type)
    return {
        "indicators": [IndicatorResponse(**i.to_dict()).dict() for i in indicators]
    }


@app.post("/api/intel/check/domain", response_model=DomainCheckResponse)
async def check_domain(request: DomainCheckRequest):
    """Check a domain against threat intelligence"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    alert = threat_matcher.check_domain(request.domain)
    if alert:
        return DomainCheckResponse(
            domain=request.domain,
            matched=True,
            indicator={
                "indicator": alert.indicator,
                "type": alert.indicator_type,
                "source": alert.feed_source
            }
        )

    return DomainCheckResponse(
        domain=request.domain,
        matched=False
    )


@app.post("/api/intel/check/ip")
async def check_ip(ip: str):
    """Check an IP against threat intelligence"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    alert = threat_matcher.check_ip(ip)
    if alert:
        return {
            "ip": ip,
            "matched": True,
            "indicator": {
                "indicator": alert.indicator,
                "type": alert.indicator_type,
                "source": alert.feed_source
            }
        }

    return {"ip": ip, "matched": False}


# --- Capture Control Endpoints ---

@app.post("/api/capture/lan/start")
async def start_lan_capture():
    """Start PCAP capture on LAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.start_lan_capture()
    if result:
        return {"status": "started", "pcap_id": result}
    return {"status": "failed", "message": "Capture may already be running"}


@app.post("/api/capture/lan/stop")
async def stop_lan_capture():
    """Stop PCAP capture on LAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.stop_lan_capture()
    return {"status": "stopped" if result else "failed"}


@app.post("/api/capture/wan/start")
async def start_wan_capture():
    """Start PCAP capture on WAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.start_wan_capture()
    if result:
        return {"status": "started", "pcap_id": result}
    return {"status": "failed", "message": "Capture may already be running"}


@app.post("/api/capture/wan/stop")
async def stop_wan_capture():
    """Stop PCAP capture on WAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.stop_wan_capture()
    return {"status": "stopped" if result else "failed"}


@app.get("/api/capture/status")
async def get_capture_status():
    """Get capture status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return {
        "active": threat_matcher.pcap_capture.get_active_captures()
    }


# --- Feed Update Endpoints ---

@app.post("/api/feeds/update/misp")
async def update_misp_feed():
    """Manually trigger MISP feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_misp()
    return {"status": "updated", "indicators_count": count}


@app.post("/api/feeds/update/pfblocker")
async def update_pfblocker_feed():
    """Manually trigger pfBlocker feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_pfblocker()
    return {"status": "updated", "indicators_count": count}


@app.post("/api/feeds/update/all")
async def update_all_feeds():
    """Manually trigger all feed updates"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    threat_matcher._update_feeds()
    return {"status": "updated"}


# --- System Endpoints ---

@app.get("/api/status")
async def get_system_status():
    """Get full system status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.get_status()
