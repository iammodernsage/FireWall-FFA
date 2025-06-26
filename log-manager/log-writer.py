#!/usr/bin/env python3
import json
import logging
import logging.handlers
import gzip
import os
import time
from pathlib import Path
from datetime import datetime
import threading
import queue
import socket
import zstandard as zstd
from typing import Dict, Any, Optional, List
import mmap
import uuid
import hashlib
from cryptography.fernet import Fernet
from prometheus_client import start_http_server, Counter, Gauge, Histogram
import pickle

# Configure module-level logger
logger = logging.getLogger(__name__)

# Prometheus Metrics
METRICS_PORT = 9091
LOG_WRITE_COUNTER = Counter('log_writes_total', 'Total log entries written', ['log_type'])
LOG_WRITE_ERRORS = Counter('log_write_errors_total', 'Total log write errors')
LOG_QUEUE_SIZE = Gauge('log_queue_size', 'Current log queue size')
LOG_BYTES_WRITTEN = Counter('log_bytes_written_total', 'Total bytes written to log files')
LOG_ROTATIONS = Counter('log_rotations_total', 'Total log file rotations')
COMPRESSION_RATIO = Histogram('log_compression_ratio', 'Compression ratio achieved', buckets=[0.1, 0.25, 0.5, 0.75, 1.0])
ENCRYPTION_TIME = Histogram('log_encryption_seconds', 'Time spent encrypting log entries')

class SecureLogWriter:

    def __init__(self, config_path: str = "/etc/FireWall-FFA/logging.yaml"):
        self.config = self._load_config(config_path)
        self._setup_log_dirs()
        self.queue = queue.Queue(maxsize=self.config['max_queue_size'])
        self._shutdown_flag = False
        self._worker_thread = None
        self._current_file = None
        self._current_file_path = None
        self._current_file_size = 0
        self._compression_ctx = self._init_zstd_compressor()
        self._cipher = self._init_encryption()
        self._zstd_dict = self._load_zstd_dict()
        self._start_metrics_server()
        self._start_worker()

    def _load_config(self, config_path: str) -> Dict[str, Any]:

        defaults = {
            "log_dir": "/var/log/FireWall-FFA",
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "retention_days": 30,
            "rotation_interval": "daily",
            "compression": "zstd",
            "max_queue_size": 10000,
            "file_permissions": 0o640,
            "host_id": socket.gethostname(),
            "log_format": "json",
            "buffer_size": 8192,
            "enable_checksum": True,
            "enable_encryption": True,
            "encryption_key_path": "/etc/FireWall-FFA/logging.key",
            "zstd_dict_path": "/etc/FireWall-FFA/zstd.dict",
            "metrics_port": METRICS_PORT,
            "metrics_enabled": True
        }

        try:
            with open(config_path) as f:
                import yaml
                user_config = yaml.safe_load(f) or {}
                return {**defaults, **user_config.get('logging', {})}
        except Exception as e:
            logger.warning(f"Using default config due to error: {str(e)}")
            return defaults

    def _init_zstd_compressor(self) -> zstd.ZstdCompressor:
        """Initialize Zstd compressor with dictionary if available"""
        if self._zstd_dict:
            return zstd.ZstdCompressor(
                level=3,
                dict_data=self._zstd_dict,
                threads=2
            )
        return zstd.ZstdCompressor(level=3)

    def _load_zstd_dict(self) -> Optional[zstd.ZstdDict]:
        """Load Zstd training dictionary for better compression"""
        try:
            if os.path.exists(self.config['zstd_dict_path']):
                with open(self.config['zstd_dict_path'], 'rb') as f:
                    return zstd.ZstdDict(f.read())
        except Exception as e:
            logger.warning(f"Failed to load Zstd dictionary: {str(e)}")
        return None

    def _init_encryption(self) -> Optional[Fernet]:
        """Initialize encryption cipher"""
        if not self.config['enable_encryption']:
            return None

        try:
            if os.path.exists(self.config['encryption_key_path']):
                with open(self.config['encryption_key_path'], 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(self.config['encryption_key_path'], 'wb') as f:
                    f.write(key)
                os.chmod(self.config['encryption_key_path'], 0o400)

            return Fernet(key)
        except Exception as e:
            logger.error(f"Encryption initialization failed: {str(e)}")
            return None

    def _start_metrics_server(self) -> None:
        """Start Prometheus metrics server if enabled"""
        if self.config['metrics_enabled']:
            try:
                start_http_server(self.config['metrics_port'])
                logger.info(f"Metrics server started on port {self.config['metrics_port']}")
            except Exception as e:
                logger.error(f"Failed to start metrics server: {str(e)}")

    def _process_queue(self) -> None:

        while not self._shutdown_flag or not self.queue.empty():
            LOG_QUEUE_SIZE.set(self.queue.qsize())

            try:
                entry = self.queue.get(timeout=1)
                if entry is None:
                    break

                with ENCRYPTION_TIME.time():
                    self._write_entry(entry)

                LOG_WRITE_COUNTER.labels(log_type=entry.get('log_type', 'unknown')).inc()
                self.queue.task_done()
            except queue.Empty:
                self._rotate_file()
                continue
            except Exception as e:
                LOG_WRITE_ERRORS.inc()
                logger.error(f"Error processing log entry: {str(e)}")

        self._close_current_file()

    def _write_entry(self, entry: Dict[str, Any]) -> None:
        """Write a single log entry with encryption and compression"""
        if not self._current_file:
            self._open_new_file()

        try:
            # Add metadata
            entry.update({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "host_id": self.config['host_id'],
                "log_id": str(uuid.uuid4())
            })

            if self.config['enable_checksum']:
                entry['checksum'] = self._generate_checksum(entry)

            log_line = self._format_entry(entry)

            # Encrypt if enabled
            if self._cipher:
                log_line = self._cipher.encrypt(log_line.encode('utf-8'))
                if isinstance(log_line, bytes):
                    log_line = log_line.decode('utf-8')

            bytes_written = self._current_file.write(log_line + "\n")
            self._current_file_size += bytes_written
            LOG_BYTES_WRITTEN.inc(bytes_written)
        except Exception as e:
            LOG_WRITE_ERRORS.inc()
            logger.error(f"Failed to write log entry: {str(e)}")
            raise

    def _compress_file(self, file_path: str) -> None:
        """Compress log file with Zstandard and measure ratio"""
        if not file_path.endswith('.zstd'):
            return

        try:
            original_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f_in:
                original_data = f_in.read()
                compressed_data = self._compression_ctx.compress(original_data)

                with open(f"{file_path}.zst", 'wb') as f_out:
                    f_out.write(compressed_data)

            compressed_size = os.path.getsize(f"{file_path}.zst")
            ratio = compressed_size / original_size
            COMPRESSION_RATIO.observe(ratio)

            os.unlink(file_path)
            LOG_ROTATIONS.inc()
        except Exception as e:
            LOG_WRITE_ERRORS.inc()
            logger.error(f"Compression failed: {str(e)}")

    def _open_new_file(self) -> None:
        """Open a new log file with proper permissions and metrics"""
        try:
            self._current_file_path = self._get_log_file_path()
            self._current_file = open(self._current_file_path, 'a', buffering=self.config['buffer_size'])
            os.chmod(self._current_file_path, self.config['file_permissions'])
            self._current_file_size = 0
            logger.info(f"Opened new log file: {self._current_file_path}")
        except IOError as e:
            LOG_WRITE_ERRORS.inc()
            logger.error(f"Failed to open log file: {str(e)}")
            raise

class LogReader:
    """Enhanced log reader with decryption support"""

    def __init__(self, log_dir: str = "/var/log/FireWall-FFA",
                 encryption_key_path: str = "/etc/FireWall-FFA/logging.key",
                 zstd_dict_path: str = "/etc/FireWall-FFA/zstd.dict"):
        self.log_dir = log_dir
        self._zstd_dict = self._load_zstd_dict(zstd_dict_path)
        self._cipher = self._init_decryptor(encryption_key_path)
        self._decompression_ctx = zstd.ZstdDecompressor(dict_data=self._zstd_dict)

    def _init_decryptor(self, key_path: str) -> Optional[Fernet]:
        """Initialize decryption cipher"""
        try:
            if os.path.exists(key_path):
                with open(key_path, 'rb') as f:
                    return Fernet(f.read())
        except Exception as e:
            logger.error(f"Decryption initialization failed: {str(e)}")
        return None

    def _decrypt_entry(self, encrypted_data: str) -> str:
        """Decrypt log entry if encryption is enabled"""
        if not self._cipher:
            return encrypted_data

        try:
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')
            return self._cipher.decrypt(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return ""

    def read_logs(self, log_type: str, start_time: Optional[datetime] = None, 
                 end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Read and decrypt logs of specified type within time range"""
        logs = []
        base_dir = Path(self.log_dir) / log_type

        for log_file in sorted(base_dir.glob("*.log*")):
            if not self._should_read_file(log_file, start_time, end_time):
                continue

            try:
                file_logs = []
                if log_file.suffix == '.zst':
                    file_logs = self._read_zstd_file(log_file)
                elif log_file.suffix == '.gz':
                    file_logs = self._read_gzip_file(log_file)
                else:
                    file_logs = self._read_text_file(log_file)

                # Decrypt entries if needed
                for entry in file_logs:
                    if isinstance(entry, str):
                        decrypted = self._decrypt_entry(entry)
                        try:
                            logs.append(json.loads(decrypted))
                        except json.JSONDecodeError:
                            continue
                    elif isinstance(entry, dict):
                        logs.append(entry)
            except Exception as e:
                logger.error(f"Error reading {log_file}: {str(e)}")
                continue

        # Filter by time range
        if start_time or end_time:
            logs = [
                log for log in logs
                if self._is_in_time_range(log, start_time, end_time)
            ]

        return logs

def train_zstd_dict(log_samples: List[str], dict_path: str, dict_size: int = 100000) -> None:
    """Train a Zstandard dictionary from sample logs"""
    try:
        samples = [json.dumps(log).encode('utf-8') for log in log_samples]
        zstd_dict = zstd.train_dictionary(dict_size, samples)

        with open(dict_path, 'wb') as f:
            f.write(zstd_dict.as_bytes())

        logger.info(f"Zstd dictionary trained and saved to {dict_path}")
    except Exception as e:
        logger.error(f"Dictionary training failed: {str(e)}")
        raise

# Example usage with new features
if __name__ == "__main__":
    # Initialize logger with all features
    writer = SecureLogWriter()

    # Train Zstd dictionary (one-time setup)
    sample_logs = [
        {"event_type": "block", "source_ip": "192.168.1.1", "reason": "SQLi"},
        {"event_type": "allow", "source_ip": "10.0.0.1", "uri": "/home"}
    ]
    train_zstd_dict(sample_logs, "/tmp/zstd.dict")

    try:
        # Write sample encrypted log
        writer.write_log("waf", {
            "event_type": "block",
            "source_ip": "192.168.1.1",
            "request_uri": "/admin.php",
            "reason": "SQL injection attempt",
            "severity": "high"
        })

        # Demonstrate reading encrypted logs
        reader = LogReader(
            log_dir="/var/log/FireWall-FFA",
            encryption_key_path="/etc/FireWall-FFA/logging.key",
            zstd_dict_path="/etc/FireWall-FFA/zstd.dict"
        )

        waf_logs = reader.read_logs(
            "waf",
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow()
        )
        print(f"Found {len(waf_logs)} decrypted WAF events")

    finally:
        writer.shutdown()
