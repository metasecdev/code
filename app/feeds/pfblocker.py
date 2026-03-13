"""
pfBlockerNG Feed Integration Module
Fetches DNS blocklists from pfBlockerNG
"""

import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class PFBlockerFeed:
    """pfBlockerNG Feed manager"""

    def __init__(self, db: Database):
        self.db = db
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0
        self.enabled = False

    def is_enabled(self) -> bool:
        """Check if pfBlocker is enabled"""
        return self.enabled

    def parse_feed_url(self, url: str) -> List[str]:
        """Parse a pfBlockerNG feed URL and extract blocklist URLs"""
        try:
            session = requests.Session()
            session.headers.update({
                "User-Agent": "CIG/1.0 pfBlockerNG Feed Fetcher"
            })
            response = session.get(url, timeout=30)
            response.raise_for_status()

            # Parse the aliasloader file to find blocklist URLs
            content = response.text
            urls = []

            # Extract URLs from the shell script format
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("http://") or line.startswith("https://"):
                    urls.append(line.rstrip("/"))
                elif line.startswith("alias_"):
                    # This is a local alias definition
                    pass

            return urls
        except Exception as e:
            logger.error(f"Failed to parse pfBlocker feed URL {url}: {e}")
            return []

    def fetch_blocklist(self, url: str) -> List[str]:
        """Fetch a blocklist from URL"""
        try:
            session = requests.Session()
            session.headers.update({
                "User-Agent": "CIG/1.0 Blocklist Fetcher"
            })
            response = session.get(url, timeout=60)
            response.raise_for_status()

            # Parse blocklist entries
            entries = []
            for line in response.text.split("\n"):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#") or line.startswith("//"):
                    continue

                # Remove any comments at end of line
                line = line.split("#")[0].split("//")[0].strip()

                if line:
                    entries.append(line)

            return entries
        except Exception as e:
            logger.error(f"Failed to fetch blocklist from {url}: {e}")
            return []

    def parse_entry(self, entry: str) -> Optional[Dict[str, str]]:
        """Parse a blocklist entry to determine type and value"""
        entry = entry.strip()

        # IPv4 address
        ipv4_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/(\d{1,2}))?$'
        match = re.match(ipv4_pattern, entry)
        if match:
            return {"type": "ip", "value": match.group(1)}

        # IPv6 address (simplified)
        if ":" in entry and not entry.startswith("http"):
            return {"type": "ip", "value": entry}

        # Domain
        if "/" not in entry and not entry[0].isdigit():
            # Simple domain validation
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$', entry):
                return {"type": "domain", "value": entry}

        return None

    def fetch_from_feeds(self, feed_urls: List[str]) -> int:
        """Fetch and process blocklists from multiple feeds"""
        if not feed_urls:
            logger.warning("No pfBlocker feed URLs configured")
            return 0

        all_indicators = []
        now = datetime.utcnow().isoformat()

        for feed_url in feed_urls:
            logger.info(f"Fetching pfBlocker feed: {feed_url}")

            # Try to parse as pfBlockerNG aliasloader first
            blocklist_urls = self.parse_feed_url(feed_url)

            if blocklist_urls:
                # These are URLs to actual blocklists
                for url in blocklist_urls:
                    entries = self.fetch_blocklist(url)
                    for entry in entries:
                        parsed = self.parse_entry(entry)
                        if parsed:
                            indicator = Indicator(
                                id=str(uuid.uuid4()),
                                value=parsed["value"],
                                type=parsed["type"],
                                source="pfblocker",
                                feed_id=feed_url,
                                first_seen=now,
                                last_seen=now,
                                tags="blocklist"
                            )
                            all_indicators.append(indicator)
            else:
                # Direct blocklist
                entries = self.fetch_blocklist(feed_url)
                for entry in entries:
                    parsed = self.parse_entry(entry)
                    if parsed:
                        indicator = Indicator(
                            id=str(uuid.uuid4()),
                            value=parsed["value"],
                            type=parsed["type"],
                            source="pfblocker",
                            feed_id=feed_url,
                            first_seen=now,
                            last_seen=now,
                            tags="blocklist"
                        )
                        all_indicators.append(indicator)

        if all_indicators:
            # Deduplicate by value and type
            seen = set()
            unique_indicators = []
            for ind in all_indicators:
                key = (ind.value, ind.type)
                if key not in seen:
                    seen.add(key)
                    unique_indicators.append(ind)

            self.db.bulk_insert_indicators(unique_indicators)
            self.indicators_count = len(unique_indicators)
            logger.info(f"Stored {len(unique_indicators)} pfBlocker indicators")
            self.last_update = datetime.utcnow()

        return len(all_indicators)

    def load_local_blocklist(self, filepath: str) -> int:
        """Load local blocklist file"""
        try:
            with open(filepath, "r") as f:
                entries = f.readlines()

            indicators = []
            now = datetime.utcnow().isoformat()

            for entry in entries:
                entry = entry.strip()
                if not entry or entry.startswith("#"):
                    continue

                parsed = self.parse_entry(entry)
                if parsed:
                    indicator = Indicator(
                        id=str(uuid.uuid4()),
                        value=parsed["value"],
                        type=parsed["type"],
                        source="pfblocker_local",
                        feed_id="local",
                        first_seen=now,
                        last_seen=now,
                        tags="local"
                    )
                    indicators.append(indicator)

            if indicators:
                self.db.bulk_insert_indicators(indicators)
                logger.info(f"Loaded {len(indicators)} local blocklist entries")

            return len(indicators)
        except FileNotFoundError:
            logger.warning(f"Local blocklist file not found: {filepath}")
        except Exception as e:
            logger.error(f"Failed to load local blocklist: {e}")

        return 0

    def get_status(self) -> Dict[str, Any]:
        """Get pfBlocker feed status"""
        return {
            "enabled": self.is_enabled(),
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "indicators_count": self.indicators_count
        }
