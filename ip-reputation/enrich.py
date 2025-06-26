#!/usr/bin/env python3
import ipaddress
import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import mmap
import logging
from pathlib import Path
import gzip
import csv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IPReputationEnricher:
    """Local IP reputation analysis engine with threat feed integration"""

    def __init__(self, config_path: str = "/etc/FireWall-FFA/ip-reputation/config.json"):
        self.config = self._load_config(config_path)
        self.db_path = self.config.get("database_path", "/var/lib/FireWall-FFA/ip_reputation.db")
        self.feeds_path = self.config.get("feeds_path", "/etc/FireWall-FFA/ip-reputation/feeds")
        self.cache = {}
        self._init_db()
        self._load_feeds()

    def _load_config(self, config_path: str) -> Dict:
        default_config = {
            "update_interval": 3600,  # 1 hour
            "max_cache_size": 100000,
            "auto_update": True,
            "default_ttl": 86400  # 24 hours
        }

        try:
            with open(config_path) as f:
                config = json.load(f)
                return {**default_config, **config}
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Using default config due to error: {str(e)}")
            return default_config

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    reputation_score INTEGER,
                    threat_types TEXT,
                    first_seen TIMESTAMP,
                    last_updated TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    feed_name TEXT PRIMARY KEY,
                    last_updated TIMESTAMP,
                    source_url TEXT,
                    local_path TEXT
                )
            """)
            conn.commit()

    def _load_feeds(self) -> None:
        feed_files = [
            "firehol_level1.ipset",
            "firehol_level2.ipset",
            "alienvault_reputation.ipset",
            "emerging_threats.ipset"
        ]

        for feed_file in feed_files:
            feed_path = os.path.join(self.feeds_path, feed_file)
            if os.path.exists(feed_path):
                self._process_feed_file(feed_path)

    def _process_feed_file(self, file_path: str) -> int:
        file_ext = os.path.splitext(file_path)[1].lower()
        processed_count = 0

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            try:
                if file_ext in ('.ipset', '.netset'):
                    processed_count = self._process_ipset_file(cursor, file_path)
                elif file_ext == '.csv':
                    processed_count = self._process_csv_file(cursor, file_path)
                elif file_ext == '.json':
                    processed_count = self._process_json_file(cursor, file_path)
                elif file_ext == '.gz':
                    processed_count = self._process_gzip_file(cursor, file_path)

                conn.commit()
                logger.info(f"Processed {processed_count} entries from {file_path}")
                return processed_count
            except Exception as e:
                conn.rollback()
                logger.error(f"Error processing {file_path}: {str(e)}")
                return 0

    def _process_ipset_file(self, cursor: sqlite3.Cursor, file_path: str) -> int:
        count = 0
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                try:
                    # Handle both individual IPs and CIDR ranges
                    network = ipaddress.ip_network(line, strict=False)
                    threat_type = os.path.basename(file_path).split('.')[0]

                    # Insert each IP in the network
                    for ip in network.hosts():
                        self._upsert_ip(
                            cursor,
                            str(ip),
                            threat_type=threat_type,
                            score=self._threat_score(threat_type)
                        )
                        count += 1
                except ValueError:
                    continue
        return count

    def _process_csv_file(self, cursor: sqlite3.Cursor, file_path: str) -> int:
        count = 0
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    ip = row.get('ip', row.get('address'))
                    if not ip:
                        continue

                    threat_type = row.get('threat_type', 'unknown')
                    score = int(row.get('score', self._threat_score(threat_type)))

                    self._upsert_ip(
                        cursor,
                        ip,
                        threat_type=threat_type,
                        score=score
                    )
                    count += 1
                except (ValueError, KeyError):
                    continue
        return count

    def _process_json_file(self, cursor: sqlite3.Cursor, file_path: str) -> int:
        count = 0
        with open(file_path, 'r') as f:
            data = json.load(f)
            for entry in data.get('malicious_ips', []):
                try:
                    ip = entry.get('ip')
                    threat_type = entry.get('type', 'unknown')
                    score = entry.get('score', self._threat_score(threat_type))

                    self._upsert_ip(
                        cursor,
                        ip,
                        threat_type=threat_type,
                        score=score
                    )
                    count += 1
                except (ValueError, KeyError, AttributeError):
                    continue
        return count

    def _process_gzip_file(self, cursor: sqlite3.Cursor, file_path: str) -> int:
        with gzip.open(file_path, 'rt') as f:
            # Decompress to temp file and process based on content
            temp_path = f"/tmp/{os.path.basename(file_path)}.decompressed"
            with open(temp_path, 'w') as temp_file:
                temp_file.write(f.read())

            count = self._process_feed_file(temp_path)
            os.unlink(temp_path)
            return count

    def _threat_score(self, threat_type: str) -> int:

        threat_scores = {
            'malware': 100,
            'botnet': 90,
            'spam': 70,
            'scanner': 75,
            'bruteforce': 70,
            'phishing': 85,
            'exploit': 75,
            'unknown': 50
        }
        return threat_scores.get(threat_type.lower(), 50)

    def _upsert_ip(self, cursor: sqlite3.Cursor, ip: str,
                  threat_type: str, score: int) -> None:
        """Insert or update IP reputation record"""
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.config['default_ttl'])

        cursor.execute("""
            INSERT OR REPLACE INTO ip_reputation (
                ip, reputation_score, threat_types, 
                first_seen, last_updated, expires_at
            ) VALUES (?, ?, ?, 
                COALESCE((SELECT first_seen FROM ip_reputation WHERE ip = ?), ?),
                ?, ?
            )
        """, (
            ip,
            score,
            threat_type,
            ip, now,  # For first_seen
            now,       # last_updated
            expires_at
        ))

    def check_ip(self, ip: str) -> Optional[Dict]:
        """Check IP reputation with caching"""
        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None

        # Check cache first
        if ip in self.cache:
            entry = self.cache[ip]
            if entry['expires_at'] > datetime.utcnow():
                return entry
            del self.cache[ip]

        # Query database
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ip, reputation_score, threat_types,
                       first_seen, last_updated, expires_at
                FROM ip_reputation
                WHERE ip = ? AND expires_at > ?
            """, (ip, datetime.utcnow()))

            row = cursor.fetchone()
            if not row:
                return None

            result = dict(row)
            self._update_cache(result)
            return result

    def _update_cache(self, entry: Dict) -> None:
        """Update LRU cache"""
        if len(self.cache) >= self.config['max_cache_size']:
            # Remove oldest entries
            oldest = sorted(self.cache.items(), key=lambda x: x[1]['last_updated'])[:100]
            for ip, _ in oldest:
                del self.cache[ip]

        self.cache[entry['ip']] = entry

    def update_feeds(self) -> bool:
        """Update all threat feeds from source files"""
        success = True
        for feed_file in os.listdir(self.feeds_path):
            feed_path = os.path.join(self.feeds_path, feed_file)
            if os.path.isfile(feed_path):
                if not self._process_feed_file(feed_path):
                    success = False
        return success

    def export_to_json(self, output_path: str) -> bool:
        """Export reputation data to JSON file"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ip, reputation_score, threat_types
                    FROM ip_reputation
                    WHERE expires_at > ?
                """, (datetime.utcnow(),))

                data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'malicious_ips': [dict(row) for row in cursor.fetchall()]
                }

                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)

                return True
        except Exception as e:
            logger.error(f"Export failed: {str(e)}")
            return False

# Example usage
if __name__ == "__main__":
    enricher = IPReputationEnricher()

    # Check an IP
    result = enricher.check_ip("192.168.1.1")
    print(f"IP Reputation: {json.dumps(result, indent=2)}")

    # Update feeds
    if enricher.update_feeds():
        print("Threat feeds updated successfully")

    # Export data
    enricher.export_to_json("/tmp/ip_reputation_export.json")
