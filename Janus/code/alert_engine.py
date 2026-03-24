"""
Honeypot Erken Uyarı Sistemi - Akıllı Alarm Modülü
====================================================
Saldırı desenlerini gerçek zamanlı analiz ederek;
- Kaba kuvvet (brute-force) tespiti
- Port tarama tespiti
- Zararlı yazılım yükleme tespiti
- Yetki yükseltme girişimi tespiti
- Anomali bazlı erken uyarı

mekanizmalarını çalıştırır.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from logger import HoneypotLogger


class AlertEngine:
    """
    Olay tabanlı erken uyarı motoru.
    Yapılandırmadaki eşik değerlerine göre alarm üretir.
    """

    def __init__(self, config: dict, hp_logger: HoneypotLogger):
        alert_cfg = config.get("alerting", {})
        thresholds = alert_cfg.get("thresholds", {})

        self.enabled = alert_cfg.get("enabled", True)
        self.hp_logger = hp_logger

        # Eşik değerleri
        self.bf_attempts = thresholds.get("brute_force_attempts", 5)
        self.bf_window = thresholds.get("brute_force_window_sec", 60)
        self.scan_ports = thresholds.get("port_scan_ports", 10)
        self.scan_window = thresholds.get("port_scan_window_sec", 30)
        self.malware_alert = thresholds.get("malware_upload_alert", True)
        self.priv_keywords = thresholds.get(
            "privilege_escalation_keywords", []
        )

        # IP bazlı olay izleme
        self._auth_failures = defaultdict(list)   # IP → [timestamp, ...]
        self._port_access = defaultdict(set)       # IP → {port, ...}
        self._port_timestamps = defaultdict(list)  # IP → [timestamp, ...]
        self._seen_alerts = set()                  # Tekrar alarm engelleme
        self._lock = threading.Lock()

        # İstatistikler
        self.stats = {
            "total_alerts": 0,
            "brute_force": 0,
            "port_scan": 0,
            "malware_upload": 0,
            "privilege_escalation": 0,
            "sql_injection": 0,
            "xss": 0,
            "other": 0,
        }
        self._stats_lock = threading.Lock()

    def process_alert(self, alert_type: str, severity: str, src_ip: str,
                      description: str, evidence: dict = None):
        """
        Alarm üretme noktası. Tüm honeypot modülleri bu callback'i çağırır.
        """
        if not self.enabled:
            return

        # Alarm kaydı
        self.hp_logger.log_alert(
            alert_type=alert_type,
            severity=severity,
            src_ip=src_ip,
            description=description,
            evidence=evidence,
        )

        # İstatistik güncelle
        with self._stats_lock:
            self.stats["total_alerts"] += 1
            category = alert_type if alert_type in self.stats else "other"
            self.stats[category] = self.stats.get(category, 0) + 1

    def track_auth_failure(self, src_ip: str, service: str):
        """
        Başarısız kimlik doğrulama girişimini izle.
        Eşik aşılırsa otomatik alarm üret.
        """
        now = time.time()
        with self._lock:
            self._auth_failures[src_ip].append(now)

            # Zaman penceresinin dışındaki kayıtları temizle
            self._auth_failures[src_ip] = [
                t for t in self._auth_failures[src_ip]
                if now - t <= self.bf_window
            ]

            count = len(self._auth_failures[src_ip])

            if count >= self.bf_attempts:
                alert_key = f"bf_{src_ip}_{service}_{int(now // self.bf_window)}"
                if alert_key not in self._seen_alerts:
                    self._seen_alerts.add(alert_key)
                    self.process_alert(
                        alert_type="brute_force",
                        severity="high",
                        src_ip=src_ip,
                        description=(
                            f"{service.upper()} kaba kuvvet saldırısı: "
                            f"{count} başarısız deneme / "
                            f"{self.bf_window}s pencere"
                        ),
                        evidence={
                            "service": service,
                            "attempts_in_window": count,
                            "window_seconds": self.bf_window,
                            "threshold": self.bf_attempts,
                        },
                    )

    def track_port_access(self, src_ip: str, port: int):
        """
        Port erişimini izle. Çok sayıda farklı port = tarama tespiti.
        """
        now = time.time()
        with self._lock:
            self._port_access[src_ip].add(port)
            self._port_timestamps[src_ip].append(now)

            # Zaman penceresi dışını temizle
            self._port_timestamps[src_ip] = [
                t for t in self._port_timestamps[src_ip]
                if now - t <= self.scan_window
            ]

            unique_ports = len(self._port_access[src_ip])

            if unique_ports >= self.scan_ports:
                alert_key = f"scan_{src_ip}_{int(now // self.scan_window)}"
                if alert_key not in self._seen_alerts:
                    self._seen_alerts.add(alert_key)
                    self.process_alert(
                        alert_type="port_scan",
                        severity="medium",
                        src_ip=src_ip,
                        description=(
                            f"Port tarama tespit edildi: "
                            f"{unique_ports} farklı port / "
                            f"{self.scan_window}s pencere"
                        ),
                        evidence={
                            "unique_ports": unique_ports,
                            "ports": list(self._port_access[src_ip]),
                            "window_seconds": self.scan_window,
                        },
                    )

    def check_privilege_escalation(self, command: str, src_ip: str,
                                   service: str):
        """Komutta yetki yükseltme kalıbı var mı kontrol et."""
        cmd_lower = command.lower()
        for keyword in self.priv_keywords:
            if keyword.lower() in cmd_lower:
                self.process_alert(
                    alert_type="privilege_escalation",
                    severity="critical",
                    src_ip=src_ip,
                    description=(
                        f"Yetki yükseltme girişimi [{service.upper()}]: "
                        f"'{command}'"
                    ),
                    evidence={
                        "command": command,
                        "matched_keyword": keyword,
                        "service": service,
                    },
                )
                return True
        return False

    def get_stats(self) -> dict:
        """Alarm istatistiklerini döndür."""
        with self._stats_lock:
            return dict(self.stats)

    def get_top_attackers(self, top_n: int = 10) -> list:
        """En aktif saldırgan IP'lerini döndür."""
        with self._lock:
            ip_scores = {}
            for ip, timestamps in self._auth_failures.items():
                ip_scores[ip] = ip_scores.get(ip, 0) + len(timestamps)
            for ip, ports in self._port_access.items():
                ip_scores[ip] = ip_scores.get(ip, 0) + len(ports)

        sorted_ips = sorted(
            ip_scores.items(), key=lambda x: x[1], reverse=True
        )
        return [
            {"ip": ip, "score": score}
            for ip, score in sorted_ips[:top_n]
        ]

    def cleanup_old_data(self):
        """Eski izleme verilerini temizle (bellek yönetimi)."""
        now = time.time()
        max_age = 3600  # 1 saat

        with self._lock:
            for ip in list(self._auth_failures.keys()):
                self._auth_failures[ip] = [
                    t for t in self._auth_failures[ip]
                    if now - t <= max_age
                ]
                if not self._auth_failures[ip]:
                    del self._auth_failures[ip]

            for ip in list(self._port_timestamps.keys()):
                self._port_timestamps[ip] = [
                    t for t in self._port_timestamps[ip]
                    if now - t <= max_age
                ]
                if not self._port_timestamps[ip]:
                    del self._port_timestamps[ip]
                    self._port_access.pop(ip, None)

            # Eski alarm anahtarlarını temizle
            cutoff = int(now // 3600)
            self._seen_alerts = {
                k for k in self._seen_alerts
                if not k.split("_")[-1].isdigit()
                or int(k.split("_")[-1]) >= cutoff - 1
            }
