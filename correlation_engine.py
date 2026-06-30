"""
Multi-Service Kill Chain Correlation Engine
============================================
Aynı IP'nin HTTP → FTP → SSH servislerinde izini sürer.
MITRE ATT&CK aşamalarını otomatik olarak haritalar ve
çok aşamalı saldırı (kill chain) tespitinde alarm üretir.

Kill Chain Aşamaları (MITRE ATT&CK):
  T1595  Reconnaissance        — HTTP tarama, 4xx tepkileri
  T1190  Initial Access        — .env/admin/wp erişimi, web login
  T1110  Credential Access     — SSH/FTP brute-force
  T1059  Execution             — Sandbox'ta komut çalıştırma
  T1548  Privilege Escalation  — sudo, shadow, chmod+s
  T1071  Command & Control     — wget/curl/nc dışarı
  T1048  Exfiltration          — FTP dosya indirme

Engine her 30 saniyede otomatik korelasyon yapar;
tamamlanan kill chain'ler için tek seferlik kritik alarm üretir.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable

# ------------------------------------------------------------------ #
#  MITRE ATT&CK eşleme tablosu
# ------------------------------------------------------------------ #
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Initial Access",
    "Credential Access",
    "Execution",
    "Privilege Escalation",
    "Command & Control",
    "Exfiltration",
]

STAGE_ORDER = {s: i for i, s in enumerate(KILL_CHAIN_STAGES)}

MITRE_MAP = {
    "Reconnaissance":       "T1595 - Active Scanning",
    "Initial Access":       "T1190 - Exploit Public-Facing Application",
    "Credential Access":    "T1110 - Brute Force",
    "Execution":            "T1059 - Command & Scripting Interpreter",
    "Privilege Escalation": "T1548 - Abuse Elevation Control Mechanism",
    "Command & Control":    "T1071 - Application Layer Protocol",
    "Exfiltration":         "T1048 - Exfiltration Over Alternative Protocol",
}


# ------------------------------------------------------------------ #
#  IP oturum kaydı
# ------------------------------------------------------------------ #
class IPSession:
    """Tek bir IP adresinin çok servisli aktivite kaydı."""

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        # stage → list of event dicts
        self.events: dict[str, list] = defaultdict(list)
        # Hangi servisler görüldü
        self.services: set[str] = set()
        # Kill chain tamamlandı mı (tekrar alarm engelleme)
        self.kill_chain_alerted = False
        self._lock = threading.Lock()

    def add_event(self, stage: str, service: str, detail: dict):
        now = time.time()
        with self._lock:
            self.last_seen = now
            self.services.add(service)
            self.events[stage].append({
                "ts": now,
                "service": service,
                **detail,
            })

    def reached_stages(self) -> list[str]:
        """Ulaşılan aşamaları sırayla döndür."""
        return sorted(
            [s for s in self.events if self.events[s]],
            key=lambda s: STAGE_ORDER.get(s, 99),
        )

    def stage_count(self) -> int:
        return len(self.reached_stages())

    def duration_sec(self) -> float:
        return self.last_seen - self.first_seen

    def timeline(self) -> list[dict]:
        """Tüm olayları kronolojik sırayla döndür."""
        flat = []
        for stage, evts in self.events.items():
            for e in evts:
                flat.append({"stage": stage, **e})
        flat.sort(key=lambda x: x["ts"])
        return flat

    def to_dict(self) -> dict:
        stages = self.reached_stages()
        return {
            "ip": self.ip,
            "first_seen": datetime.fromtimestamp(
                self.first_seen, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(
                self.last_seen, tz=timezone.utc).isoformat(),
            "duration_sec": round(self.duration_sec(), 1),
            "services_seen": sorted(self.services),
            "stages_reached": stages,
            "stage_count": len(stages),
            "mitre_ids": [MITRE_MAP[s] for s in stages if s in MITRE_MAP],
            "timeline": self.timeline(),
        }


# ------------------------------------------------------------------ #
#  Correlation Engine
# ------------------------------------------------------------------ #
class CorrelationEngine:
    """
    Servisler arası olay korelasyonu ve kill chain tespiti.

    Kullanım:
        engine = CorrelationEngine(config, hp_logger, alert_callback)
        engine.start()
        # Herhangi bir modülden:
        engine.record_event(ip, stage, service, detail_dict)
    """

    def __init__(self, config: dict, hp_logger, alert_callback: Callable):
        corr_cfg = config.get("correlation", {})
        self._min_stages = corr_cfg.get("kill_chain_min_stages", 3)
        self._min_services = corr_cfg.get("kill_chain_min_services", 2)
        self._check_interval = corr_cfg.get("check_interval_sec", 30)
        self._session_ttl = corr_cfg.get("session_ttl_sec", 7200)  # 2 saat
        self._enabled = corr_cfg.get("enabled", True)

        self._hp_logger = hp_logger
        self._alert_callback = alert_callback
        self._sessions: dict[str, IPSession] = {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: threading.Thread | None = None

    # -------------------------------------------------------------- #
    #  Olay kayıt API'si — diğer modüllerden çağrılır
    # -------------------------------------------------------------- #

    def record_event(self, ip: str, stage: str, service: str,
                     detail: dict | None = None):
        """
        Bir olayı belirli bir kill chain aşamasına kaydeder.

        ip      : Kaynak IP
        stage   : KILL_CHAIN_STAGES içinde bir değer
        service : "http" | "ftp" | "ssh"
        detail  : Olay ayrıntıları (path, command, username …)
        """
        if not self._enabled or stage not in STAGE_ORDER:
            return
        with self._lock:
            if ip not in self._sessions:
                self._sessions[ip] = IPSession(ip)
            self._sessions[ip].add_event(stage, service, detail or {})

    # -------------------------------------------------------------- #
    #  Yaygın olay sınıflandırıcıları (kolaylık sarmalayıcılar)
    # -------------------------------------------------------------- #

    def on_http_request(self, ip: str, path: str, status: int,
                        method: str = "GET"):
        path_lc = path.lower()
        if status >= 400:
            self.record_event(ip, "Reconnaissance", "http",
                              {"path": path, "status": status, "method": method})
        elif any(p in path_lc for p in ("/.env", "/admin", "/wp-", "/phpmyadmin",
                                         "/config", "/.git", "/backup")):
            self.record_event(ip, "Initial Access", "http",
                              {"path": path, "status": status, "method": method})

    def on_web_login(self, ip: str, path: str, status: int):
        self.record_event(ip, "Initial Access", "http",
                          {"path": path, "status": status, "event": "login_post"})

    def on_auth_attempt(self, ip: str, service: str, username: str,
                        success: bool):
        self.record_event(ip, "Credential Access", service,
                          {"username": username, "success": success})

    def on_env_accessed(self, ip: str):
        self.record_event(ip, "Initial Access", "http",
                          {"event": "env_file_leaked"})

    def on_command(self, ip: str, command: str, session_id: str = ""):
        self.record_event(ip, "Execution", "ssh",
                          {"command": command, "session_id": session_id})
        cmd_lc = command.lower()
        if any(k in cmd_lc for k in ("sudo", "su root", "chmod +s",
                                      "/etc/shadow", "/etc/passwd")):
            self.record_event(ip, "Privilege Escalation", "ssh",
                              {"command": command})
        if any(k in cmd_lc for k in ("wget", "curl", "nc -e", "bash -i",
                                      "python -c", "/dev/tcp")):
            self.record_event(ip, "Command & Control", "ssh",
                              {"command": command})

    def on_ftp_download(self, ip: str, filename: str):
        self.record_event(ip, "Exfiltration", "ftp",
                          {"filename": filename})

    def on_credential_reuse(self, ip: str, username: str):
        """Web'den çalınan credential ile SSH/FTP girişi → Initial Access kapanışı."""
        self.record_event(ip, "Initial Access", "ssh",
                          {"event": "credential_reuse", "username": username})

    # -------------------------------------------------------------- #
    #  Arka plan korelasyon döngüsü
    # -------------------------------------------------------------- #

    def start(self):
        if not self._enabled:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="correlation-engine", daemon=True
        )
        self._thread.start()
        self._hp_logger.logger.info(
            "Correlation Engine başlatıldı (min_stages=%d, min_services=%d)",
            self._min_stages, self._min_services,
        )

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(self._check_interval)
            try:
                self._check_all()
                self._evict_old_sessions()
            except Exception as e:
                self._hp_logger.logger.debug("correlation loop hata: %s", e)

    def _check_all(self):
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            self._evaluate(session)

    def _evaluate(self, session: IPSession):
        """Kill chain tamamlanma koşulunu kontrol et ve alarm üret."""
        stages = session.reached_stages()
        if (len(stages) >= self._min_stages
                and len(session.services) >= self._min_services
                and not session.kill_chain_alerted):

            session.kill_chain_alerted = True
            duration = session.duration_sec()
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            secs = int(duration % 60)

            dur_str = (f"{hours}s {minutes}dk {secs}sn" if hours
                       else f"{minutes}dk {secs}sn" if minutes
                       else f"{secs}sn")

            mitre_ids = [MITRE_MAP[s] for s in stages if s in MITRE_MAP]

            self._alert_callback(
                alert_type="kill_chain_detected",
                severity="critical",
                src_ip=session.ip,
                description=(
                    f"Çok aşamalı saldırı kill chain tespit edildi! "
                    f"{len(stages)} aşama / {len(session.services)} servis "
                    f"/ {dur_str} içinde"
                ),
                evidence={
                    "stages": stages,
                    "services": sorted(session.services),
                    "duration_sec": round(duration, 1),
                    "duration_human": dur_str,
                    "mitre_techniques": mitre_ids,
                    "timeline": session.timeline()[-20:],  # son 20 olay
                    "first_seen": datetime.fromtimestamp(
                        session.first_seen, tz=timezone.utc).isoformat(),
                    "last_seen": datetime.fromtimestamp(
                        session.last_seen, tz=timezone.utc).isoformat(),
                },
            )

            self._hp_logger.logger.critical(
                "KILL CHAIN [%s]: %s → %s (%s)",
                session.ip, " → ".join(stages),
                sorted(session.services), dur_str,
            )

    def _evict_old_sessions(self):
        cutoff = time.time() - self._session_ttl
        with self._lock:
            stale = [ip for ip, s in self._sessions.items()
                     if s.last_seen < cutoff]
            for ip in stale:
                del self._sessions[ip]

    # -------------------------------------------------------------- #
    #  Raporlama
    # -------------------------------------------------------------- #

    def get_all_sessions(self) -> list[dict]:
        """Tüm aktif IP oturumlarını dict listesi olarak döndür."""
        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]

    def get_session(self, ip: str) -> dict | None:
        with self._lock:
            s = self._sessions.get(ip)
            return s.to_dict() if s else None

    def get_kill_chains(self) -> list[dict]:
        """Tamamlanmış kill chain'leri döndür."""
        with self._lock:
            return [
                s.to_dict() for s in self._sessions.values()
                if s.kill_chain_alerted
            ]

    def get_stats(self) -> dict:
        with self._lock:
            sessions = list(self._sessions.values())
        total = len(sessions)
        multi_service = sum(1 for s in sessions if len(s.services) >= 2)
        kill_chains = sum(1 for s in sessions if s.kill_chain_alerted)
        stage_dist: dict[str, int] = defaultdict(int)
        for s in sessions:
            for stage in s.reached_stages():
                stage_dist[stage] += 1
        return {
            "total_tracked_ips": total,
            "multi_service_attackers": multi_service,
            "kill_chains_detected": kill_chains,
            "stage_distribution": dict(stage_dist),
        }
