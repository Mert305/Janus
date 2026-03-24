"""
Honeypot Erken Uyarı Sistemi - Merkezi Loglama Modülü
=====================================================
Tüm honeypot servislerinden gelen olayları yapısal JSON formatında
kaydeder. Analiz ve erken uyarı sistemleriyle entegrasyon sağlar.
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler


class HoneypotLogger:
    """Yapısal JSON loglama sınıfı."""

    _instances: dict = {}
    _lock = threading.Lock()

    def __init__(self, config: dict):
        self.log_dir = config.get("general", {}).get("log_directory", "logs")
        os.makedirs(self.log_dir, exist_ok=True)

        # Ana olay logu (JSON-lines formatı)
        self.event_log_path = os.path.join(self.log_dir, "honeypot_events.jsonl")
        # Alarm logu
        self.alert_log_path = os.path.join(self.log_dir, "alerts.jsonl")
        # Ham komut logu
        self.command_log_path = os.path.join(self.log_dir, "commands.jsonl")

        # Python logging altyapısı
        self._setup_python_logger()

        # Olay sayacı (istatistik için)
        self._event_count = 0
        self._event_lock = threading.Lock()

    def _setup_python_logger(self):
        """Konsol + dosya tabanlı Python logger'ı yapılandır."""
        self.logger = logging.getLogger("honeypot")
        self.logger.setLevel(logging.DEBUG)

        # Konsol handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_fmt)

        # Dönen dosya handler
        file_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "honeypot.log"),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s [%(threadName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)

        if not self.logger.handlers:
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

    # ------------------------------------------------------------------
    #  Yapısal olay kaydı
    # ------------------------------------------------------------------

    def log_event(self, event_type: str, service: str, src_ip: str,
                  src_port: int, details: dict = None):
        """
        Bir honeypot olayını JSON-lines formatında kaydet.

        Parametreler:
            event_type : "connection", "auth_attempt", "command",
                         "file_upload", "scan", "exploit" vb.
            service    : "ssh", "ftp", "http"
            src_ip     : Kaynak IP adresi
            src_port   : Kaynak port numarası
            details    : Olaya özgü ek bilgiler (dict)
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        event = {
            "timestamp": timestamp,
            "event_type": event_type,
            "service": service,
            "src_ip": src_ip,
            "src_port": src_port,
            "details": details or {},
        }

        # Dosyaya yaz (thread-safe)
        with self._event_lock:
            self._event_count += 1
            event["event_id"] = self._event_count
            with open(self.event_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

        # Konsola kısa özet
        self.logger.info(
            "[%s] %s | %s:%d | %s",
            service.upper(), event_type, src_ip, src_port,
            json.dumps(details or {}, ensure_ascii=False),
        )

        return event

    def log_command(self, service: str, src_ip: str, command: str,
                    session_id: str = ""):
        """Saldırganın çalıştırdığı komutu kaydet."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": service,
            "src_ip": src_ip,
            "session_id": session_id,
            "command": command,
        }
        with self._event_lock:
            with open(self.command_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self.logger.warning(
            "[%s] KOMUT | %s | session=%s | cmd=%s",
            service.upper(), src_ip, session_id, command,
        )

    def log_alert(self, alert_type: str, severity: str, src_ip: str,
                  description: str, evidence: dict = None):
        """
        Erken uyarı / alarm kaydı.

        severity: "low", "medium", "high", "critical"
        """
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "severity": severity,
            "src_ip": src_ip,
            "description": description,
            "evidence": evidence or {},
        }
        with self._event_lock:
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")

        level_map = {
            "low": logging.INFO,
            "medium": logging.WARNING,
            "high": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        self.logger.log(
            level_map.get(severity, logging.WARNING),
            "⚠ ALARM [%s] %s | %s | %s",
            severity.upper(), alert_type, src_ip, description,
        )

        return alert

    # ------------------------------------------------------------------
    #  Yardımcı metotlar
    # ------------------------------------------------------------------

    def get_event_count(self) -> int:
        with self._event_lock:
            return self._event_count

    def read_events(self, last_n: int = 100) -> list:
        """Son N olayı oku."""
        events = []
        if not os.path.exists(self.event_log_path):
            return events
        with open(self.event_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events[-last_n:]

    def read_alerts(self, last_n: int = 50) -> list:
        """Son N alarmı oku."""
        alerts = []
        if not os.path.exists(self.alert_log_path):
            return alerts
        with open(self.alert_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
        return alerts[-last_n:]

    def read_commands(self, last_n: int = 100) -> list:
        """Son N komutu oku."""
        commands = []
        if not os.path.exists(self.command_log_path):
            return commands
        with open(self.command_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    commands.append(json.loads(line))
        return commands[-last_n:]
