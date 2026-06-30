"""
FTP Honeypot - Konteyner log tailer
===================================
Gerçek FTP protokolünü artık konteynerdeki vsftpd konuşuyor; biz onun
log dosyasını canlı tail edip her satırı honeypot event şemasına
çeviriyoruz. Brute-force, indirme ve yükleme eventleri alert_engine'e iletilir.
"""
from __future__ import annotations

import os
import re
import threading
import time

from logger import HoneypotLogger


_RE_CONNECT = re.compile(r'CONNECT:\s*Client\s+"([\d.]+)"')
_RE_LOGIN   = re.compile(r'\[(?P<user>[^\]]+)\]\s+(?P<status>OK|FAIL)\s+LOGIN:\s*Client\s+"(?P<ip>[\d.]+)"')
_RE_CMD     = re.compile(r'\[(?P<user>[^\]]+)\]\s+FTP command:\s*Client\s+"(?P<ip>[\d.]+)",\s*"(?P<cmd>[^"]*)"')
_RE_DL      = re.compile(r'\[(?P<user>[^\]]+)\]\s+DOWNLOAD:\s*Client\s+"(?P<ip>[\d.]+)",\s*"(?P<path>[^"]*)",\s*(?P<bytes>\d+)\s+bytes')
_RE_UL      = re.compile(r'\[(?P<user>[^\]]+)\]\s+UPLOAD:\s*Client\s+"(?P<ip>[\d.]+)",\s*"(?P<path>[^"]*)",\s*(?P<bytes>\d+)\s+bytes')


class FTPHoneypot:
    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_callback, alert_engine=None,
                 threat_intel=None, correlation=None):
        ftp_cfg = config.get("services", {}).get("ftp", {})
        self.bind_port = ftp_cfg.get("bind_port", 2121)
        docker_cfg = (config.get("docker") or {}).get("services", {}).get("ftp", {})
        self.log_path = docker_cfg.get("log_path", "logs/ftp/vsftpd.log")
        self.hp_logger = hp_logger
        self.alert_callback = alert_callback
        self.alert_engine = alert_engine
        self.threat_intel = threat_intel
        self.correlation = correlation
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        if not os.path.exists(self.log_path):
            open(self.log_path, "a").close()
        self._thread = threading.Thread(
            target=self._tail_loop, name="ftp-tailer", daemon=True
        )
        self._thread.start()
        self.hp_logger.logger.info(
            "FTP tailer hazır (port=%d, log=%s)", self.bind_port, self.log_path
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

            line = f.readline()
            if not line:
                time.sleep(0.4)
                continue

            self._parse_line(line.rstrip("\r\n"))

        if f:
            try: f.close()
            except Exception: pass

    def _parse_line(self, line: str):
        if not line:
            return

        m = _RE_CONNECT.search(line)
        if m:
            ip = m.group(1)
            self.hp_logger.log_event(
                event_type="connection", service="ftp",
                src_ip=ip, src_port=self.bind_port,
                details={"state": "new"},
            )
            if self.alert_engine:
                try:
                    self.alert_engine.track_connection(ip, "ftp", self.bind_port)
                except Exception as e:
                    self.hp_logger.logger.debug("alert_engine track: %s", e)
            if self.correlation:
                self.correlation.record_event(
                    ip, "Credential Access", "ftp", {"event": "connection"}
                )
            if self.threat_intel:
                try:
                    summary = self.threat_intel.summary_line(ip)
                    if summary != "no intel":
                        self.hp_logger.logger.info(
                            "ThreatIntel [FTP] %s: %s", ip, summary
                        )
                except Exception:
                    pass
            return

        m = _RE_LOGIN.search(line)
        if m:
            user, status, ip = m.group("user"), m.group("status"), m.group("ip")
            ev = "auth_success" if status == "OK" else "auth_attempt"
            self.hp_logger.log_event(
                event_type=ev, service="ftp",
                src_ip=ip, src_port=self.bind_port,
                details={"username": user, "status": status, "method": "password"},
            )
            if self.correlation:
                self.correlation.on_auth_attempt(
                    ip, "ftp", user, success=(status == "OK")
                )
            return

        m = _RE_CMD.search(line)
        if m:
            ip, cmd = m.group("ip"), m.group("cmd")
            self.hp_logger.log_command(
                service="ftp", src_ip=ip, command=cmd, session_id="",
            )
            self.hp_logger.log_event(
                event_type="command", service="ftp",
                src_ip=ip, src_port=self.bind_port,
                details={"command": cmd, "user": m.group("user")},
            )
            return

        m = _RE_DL.search(line)
        if m:
            ip = m.group("ip")
            path = m.group("path")
            intel = self.threat_intel.enrich(ip) if self.threat_intel else {}
            self.hp_logger.log_event(
                event_type="file_download", service="ftp",
                src_ip=ip, src_port=self.bind_port,
                details={
                    "user": m.group("user"),
                    "path": path,
                    "bytes": int(m.group("bytes")),
                },
            )
            if self.correlation:
                self.correlation.on_ftp_download(ip, path)
            self.alert_callback(
                alert_type="data_exfiltration",
                severity="high",
                src_ip=ip,
                description=f"FTP indirme: {path}",
                evidence={"path": path, "bytes": int(m.group("bytes")),
                          "threat_intel": intel},
            )
            return

        m = _RE_UL.search(line)
        if m:
            ip = m.group("ip")
            self.hp_logger.log_event(
                event_type="file_upload", service="ftp",
                src_ip=ip, src_port=self.bind_port,
                details={
                    "user": m.group("user"),
                    "path": m.group("path"),
                    "bytes": int(m.group("bytes")),
                },
            )
            self.alert_callback(
                alert_type="malware_upload",
                severity="critical",
                src_ip=ip,
                description=f"FTP yükleme: {m.group('path')}",
                evidence={"path": m.group("path"), "bytes": int(m.group("bytes"))},
            )
            return
