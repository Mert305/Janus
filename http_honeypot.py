"""
her isteği honeypot event şemasına çevirir. Hassas yollara erişim (/admin, /.env, /phpmyadmin
vb.), 4xx tarama ve login POST denemeleri için alarm üretir.
"""
from __future__ import annotations

import os
import re
import threading
import time

from logger import HoneypotLogger


# Apache "combined" log format
_RE_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>[^"]*?)\s+(?P<proto>\S+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)\s+'
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

_SENSITIVE_PATHS = (
    "/.env", "/admin", "/wp-admin", "/wp-login", "/phpmyadmin",
    "/backup", "/config", "/.git", "/.aws", "/api/v1/",
    "/server-status", "/console", "/actuator",
)

# IPs that accessed /.env — shared with alert_engine for credential correlation
# Format: {ip: timestamp}
env_accessed_ips: dict = {}


class HTTPHoneypot:
    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_callback, alert_engine=None,
                 threat_intel=None, correlation=None):
        http_cfg = config.get("services", {}).get("http", {})
        self.bind_port = http_cfg.get("bind_port", 8080)
        docker_cfg = (config.get("docker") or {}).get("services", {}).get("http", {})
        self.log_path = docker_cfg.get("log_path", "logs/http/access.log")
        self.hp_logger = hp_logger
        self.alert_callback = alert_callback
        self.alert_engine = alert_engine
        self.threat_intel = threat_intel
        self.correlation = correlation
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._not_found_counts: dict[str, int] = {}

    def start(self):
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        if not os.path.exists(self.log_path):
            open(self.log_path, "a").close()
        self._thread = threading.Thread(
            target=self._tail_loop, name="http-tailer", daemon=True
        )
        self._thread.start()
        self.hp_logger.logger.info(
            "HTTP tailer hazır (port=%d, log=%s)", self.bind_port, self.log_path
        )

    def stop(self):
        self._stop.set()

    def _tail_loop(self):
        f = None
        inode = None
        while not self._stop.is_set():
            try:
                st = os.stat(self.log_path)
            except FileNotFoundError:
                time.sleep(1.0)
                continue

            # Dosya ilk kez açılıyor veya yeniden oluşturulmuş (inode değişti)
            if f is None or inode != st.st_ino:
                if f:
                    try: f.close()
                    except Exception: pass
                try:
                    f = open(self.log_path, "r", encoding="utf-8", errors="replace")
                    f.seek(0, os.SEEK_END)
                    inode = st.st_ino
                except OSError:
                    time.sleep(1.0)
                    continue
            # Aynı inode ama dosya küçülmüş → log döndürüldü/truncate edildi
            # (ör. http container restart veya logrotate). Baştan oku, yoksa
            # eski offset'te takılıp yeni istekleri hiç görmeyiz.
            elif st.st_size < f.tell():
                f.seek(0)

            line = f.readline()
            if not line:
                time.sleep(0.4)
                continue

            self._parse_line(line.rstrip("\r\n"))

        if f:
            try: f.close()
            except Exception: pass

    def _parse_line(self, line: str):
        m = _RE_LINE.match(line)
        if not m:
            return
        ip = m.group("ip")
        method = m.group("method")
        path = m.group("path")
        status = int(m.group("status"))
        size = m.group("size")
        ua = m.group("ua")

        try:
            size_int = int(size) if size != "-" else 0
        except ValueError:
            size_int = 0

        self.hp_logger.log_event(
            event_type="request", service="http",
            src_ip=ip, src_port=self.bind_port,
            details={
                "method": method, "path": path,
                "status": status, "bytes": size_int,
                "user_agent": ua,
            },
        )

        if self.alert_engine:
            try:
                self.alert_engine.track_connection(ip, "http", self.bind_port)
            except Exception as e:
                self.hp_logger.logger.debug("alert_engine track: %s", e)

        # Correlation Engine — her HTTP isteğini sınıflandır
        if self.correlation:
            try:
                self.correlation.on_http_request(ip, path, status, method)
            except Exception:
                pass

        # Threat Intel — yeni IP ilk kez görüldüğünde zenginleştir (arka planda)
        if self.threat_intel and status != 404:
            try:
                summary = self.threat_intel.summary_line(ip)
                if summary != "no intel":
                    self.hp_logger.logger.debug("ThreatIntel [%s]: %s", ip, summary)
            except Exception:
                pass

        path_lc = path.lower()

        # .env özel takip — credential correlation için IP'yi kaydet
        if path_lc == "/.env" and status == 200:
            import time as _time
            env_accessed_ips[ip] = _time.time()
            intel = self.threat_intel.enrich(ip) if self.threat_intel else {}
            if self.correlation:
                self.correlation.on_env_accessed(ip)
            self.alert_callback(
                alert_type="env_file_accessed",
                severity="critical",
                src_ip=ip,
                description=f"⚠ .env dosyası ele geçirildi! SSH/FTP credential'ları açığa çıktı.",
                evidence={"path": path, "status": status, "user_agent": ua,
                          "leaked_creds": "SSH: sysadmin / FTP: ftpbackup",
                          "threat_intel": intel},
            )
        else:
            for sp in _SENSITIVE_PATHS:
                if path_lc.startswith(sp):
                    self.alert_callback(
                        alert_type="sensitive_path_access",
                        severity="medium",
                        src_ip=ip,
                        description=f"Hassas endpoint istendi: {method} {path}",
                        evidence={"path": path, "status": status, "user_agent": ua},
                    )
                    break

        if method == "POST" and "login" in path_lc:
            self.hp_logger.log_event(
                event_type="auth_attempt", service="http",
                src_ip=ip, src_port=self.bind_port,
                details={"path": path, "status": status, "method": "POST"},
            )
            if self.correlation:
                self.correlation.on_web_login(ip, path, status)

        if 400 <= status < 500:
            self._not_found_counts[ip] = self._not_found_counts.get(ip, 0) + 1
            if self._not_found_counts[ip] == 10:
                self.alert_callback(
                    alert_type="web_scan",
                    severity="medium",
                    src_ip=ip,
                    description="HTTP tarama: çok sayıda 4xx yanıt",
                    evidence={"count": self._not_found_counts[ip], "last_path": path},
                )
