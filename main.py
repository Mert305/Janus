#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  Honeypot Erken Uyarı Sistemi - Ana Orkestratör                ║
║  ─────────────────────────────────────────────────────────────  ║
║  Kurumsal ağ mimarisini hedef alan siber tehditleri tespit      ║
║  etmek ve analiz etmek üzere tasarlanmış proaktif erken         ║
║  uyarı sistemi.                                                 ║
║                                                                  ║
║  Modüller:                                                       ║
║    • SSH Honeypot  (port 2222)  - Kaba kuvvet & komut kaydı    ║
║    • FTP Honeypot  (port 2121)  - Dosya yükleme & erişim kaydı ║
║    • HTTP Honeypot (port 8080)  - Web saldırı tespiti           ║
║    • PCAP Yakalama              - Ağ trafiği kaydı              ║
║    • Erken Uyarı Motoru         - Akıllı alarm sistemi          ║
║    • Analiz & Raporlama         - HTML rapor üretimi            ║
║    • Web Dashboard              - Gerçek zamanlı izleme         ║
╚══════════════════════════════════════════════════════════════════╝

Kullanım:
    python main.py                    # Tüm servisleri başlat
    python main.py --config my.yaml   # Özel yapılandırma dosyası
    python main.py --report           # Sadece rapor üret
    python main.py --no-dashboard     # Dashboard olmadan başlat
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time

# Windows konsolunda Unicode (kutu çizgileri, ✓, ✗) hatasız yazılsın
for _stream in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _safe_print(text: str):
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.write(text.encode("ascii", "replace").decode("ascii") + "\n")
        sys.stdout.flush()

import yaml

# Proje modülleri
from logger import HoneypotLogger
from alert_engine import AlertEngine
from analyzer import Analyzer
from pcap_capture import PcapCapture
from threat_intel import ThreatIntel
from correlation_engine import CorrelationEngine


BANNER = r"""
  ╦ ╦┌─┐┌┐┌┌─┐┬ ┬┌─┐┌─┐┌┬┐  ╔═╗┬─┐┬┌─┌─┐┌┐┌  ╦ ╦┬ ┬┌─┐┬─┐┬
  ╠═╣│ ││││├┤ └┬┘├─┘│ │ │   ║╣ ├┬┘├┴┐├┤ │││  ║ ║└┬┘├─┤├┬┘│
  ╩ ╩└─┘┘└┘└─┘ ┴ ┴  └─┘ ┴   ╚═╝┴└─┴ ┴└─┘┘└┘  ╚═╝ ┴ ┴ ┴┴└─┴

  [ Kurumsal Ağ Honeypot Erken Uyarı Sistemi ]
  [ SSH | FTP | HTTP | PCAP | Analiz | Dashboard ]
"""


def load_config(config_path: str) -> dict:
    """YAML yapılandırma dosyasını yükle."""
    if not os.path.exists(config_path):
        print(f"[HATA] Yapılandırma dosyası bulunamadı: {config_path}")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    return config


class HoneypotSystem:
    """
    Ana sistem orkestratörü.
    Tüm honeypot modüllerini başlatır, yönetir ve durdurur.
    """

    def __init__(self, config: dict, no_dashboard: bool = False):
        self.config = config
        self.no_dashboard = no_dashboard

        # 1. Loglama
        self.hp_logger = HoneypotLogger(config)
        self.hp_logger.logger.info("Honeypot sistemi başlatılıyor...")

        # 2. Erken uyarı motoru
        self.alert_engine = AlertEngine(config, self.hp_logger)

        # 2b. Threat Intelligence (GeoIP + AbuseIPDB + Shodan)
        try:
            self.threat_intel = ThreatIntel(config)
        except Exception as e:
            self.hp_logger.logger.warning("ThreatIntel başlatılamadı: %s", e)
            self.threat_intel = None

        # 2c. Multi-Service Correlation Engine
        try:
            self.correlation = CorrelationEngine(
                config, self.hp_logger, self.alert_engine.process_alert
            )
        except Exception as e:
            self.hp_logger.logger.warning("CorrelationEngine başlatılamadı: %s", e)
            self.correlation = None

        # 3. Analiz modülü
        self.analyzer = Analyzer(
            config, self.hp_logger,
            correlation=self.correlation,
            threat_intel=self.threat_intel,
        )

        # 4. Sandbox Manager (Docker tabanlı SSH sandbox motoru)
        self.sandbox_manager = None
        self._init_sandbox_manager()

        # 5. Servis modülleri
        self.services = {}
        self._init_services()  # threat_intel ve correlation zaten self üzerinde

        # 5. PCAP yakalama
        self.pcap = PcapCapture(config, self.hp_logger)

        # 6. Dashboard
        self.dashboard = None
        if not no_dashboard:
            self._init_dashboard()

        # Periyodik görevler
        self._running = False

    def _init_sandbox_manager(self):
        """Docker SSH sandbox motorunu kur."""
        if not (self.config.get("docker") or {}).get("enabled", False):
            self.hp_logger.logger.info(
                "Docker devre dışı — SSH sandbox başlatılmayacak."
            )
            return
        try:
            from sandbox_manager import SandboxManager
            self.sandbox_manager = SandboxManager(self.config, self.hp_logger)
        except Exception as e:
            self.hp_logger.logger.error(
                "SandboxManager başlatılamadı: %s", e
            )
            self.sandbox_manager = None

    def _init_services(self):
        """Aktif honeypot servislerini oluştur."""
        services_cfg = self.config.get("services", {})

        # SSH Honeypot (sandbox proxy)
        if services_cfg.get("ssh", {}).get("enabled", False):
            if self.sandbox_manager is None:
                self.hp_logger.logger.warning(
                    "SSH Honeypot atlandı: sandbox_manager yok."
                )
            else:
                try:
                    from ssh_honeypot import SSHHoneypot
                    self.services["ssh"] = SSHHoneypot(
                        self.config, self.hp_logger,
                        self.alert_engine.process_alert,
                        sandbox_manager=self.sandbox_manager,
                        alert_engine=self.alert_engine,
                        threat_intel=self.threat_intel,
                        correlation=self.correlation,
                    )
                    self.hp_logger.logger.info("SSH Honeypot modülü yüklendi.")
                except ImportError as e:
                    self.hp_logger.logger.warning(
                        "SSH Honeypot yüklenemedi: %s", str(e)
                    )

        # FTP Honeypot
        if services_cfg.get("ftp", {}).get("enabled", False):
            try:
                from ftp_honeypot import FTPHoneypot
                self.services["ftp"] = FTPHoneypot(
                    self.config, self.hp_logger,
                    self.alert_engine.process_alert,
                    alert_engine=self.alert_engine,
                    threat_intel=self.threat_intel,
                    correlation=self.correlation,
                )
                self.hp_logger.logger.info("FTP Honeypot modülü yüklendi.")
            except ImportError as e:
                self.hp_logger.logger.warning(
                    "FTP Honeypot yüklenemedi: %s", str(e)
                )

        # HTTP Honeypot
        if services_cfg.get("http", {}).get("enabled", False):
            try:
                from http_honeypot import HTTPHoneypot
                self.services["http"] = HTTPHoneypot(
                    self.config, self.hp_logger,
                    self.alert_engine.process_alert,
                    alert_engine=self.alert_engine,
                    threat_intel=self.threat_intel,
                    correlation=self.correlation,
                )
                self.hp_logger.logger.info("HTTP Honeypot modülü yüklendi.")
            except ImportError as e:
                self.hp_logger.logger.warning(
                    "HTTP Honeypot yüklenemedi: %s", str(e)
                )

    def _init_dashboard(self):
        """Web dashboard'u oluştur."""
        try:
            from dashboard import Dashboard
            self.dashboard = Dashboard(
                self.config, self.hp_logger,
                self.alert_engine, self.analyzer,
                sandbox_manager=self.sandbox_manager,
                correlation=self.correlation,
                threat_intel=self.threat_intel,
            )
        except ImportError:
            self.hp_logger.logger.warning("Dashboard yüklenemedi.")

    def start(self):
        """Tüm sistemi başlat."""
        self._running = True

        _safe_print(BANNER)
        self.hp_logger.logger.info("=" * 60)
        self.hp_logger.logger.info("  HONEYPOT ERKEN UYARI SİSTEMİ BAŞLADI")
        self.hp_logger.logger.info("=" * 60)

        # Docker decoy konteynerlerini ayağa kaldır (ftp + http)
        self._compose_up()

        # Correlation Engine başlat
        if self.correlation is not None:
            try:
                self.correlation.start()
                self.hp_logger.logger.info("  ✓ Correlation Engine başlatıldı")
            except Exception as e:
                self.hp_logger.logger.warning(
                    "  ✗ Correlation Engine başlatılamadı: %s", e
                )

        # Sandbox motorunu başlat
        if self.sandbox_manager is not None:
            try:
                self.sandbox_manager.start()
                self.hp_logger.logger.info("  ✓ Sandbox motoru hazır")
            except Exception as e:
                self.hp_logger.logger.error(
                    "  ✗ Sandbox motoru başlatılamadı: %s", e
                )

        # Servisleri başlat
        for name, service in self.services.items():
            try:
                service.start()
                self.hp_logger.logger.info("  ✓ %s servisi başlatıldı", name.upper())
            except Exception as e:
                self.hp_logger.logger.error(
                    "  ✗ %s servisi başlatılamadı: %s", name.upper(), str(e)
                )

        # PCAP yakalama başlat
        try:
            self.pcap.start()
            self.hp_logger.logger.info("  ✓ PCAP yakalama başlatıldı")
        except Exception as e:
            self.hp_logger.logger.warning(
                "  ✗ PCAP başlatılamadı: %s", str(e)
            )

        # Dashboard başlat
        if self.dashboard and self.dashboard.enabled:
            try:
                self.dashboard.start()
                self.hp_logger.logger.info(
                    "  ✓ Dashboard: http://%s:%d",
                    self.config.get("dashboard", {}).get("bind_host", "127.0.0.1"),
                    self.config.get("dashboard", {}).get("bind_port", 5000),
                )
            except Exception as e:
                self.hp_logger.logger.warning(
                    "  ✗ Dashboard başlatılamadı: %s", str(e)
                )

        # Periyodik görevler
        self._start_periodic_tasks()

        self.hp_logger.logger.info("=" * 60)
        self.hp_logger.logger.info("  Sistem hazır - saldırı bekleniyor...")
        self.hp_logger.logger.info("  Durdurmak için Ctrl+C")
        self.hp_logger.logger.info("=" * 60)

    def stop(self):
        """Tüm sistemi durdur."""
        self._running = False
        self.hp_logger.logger.info("Sistem durduruluyor...")

        # Servisleri durdur
        for name, service in self.services.items():
            try:
                service.stop()
                self.hp_logger.logger.info("  %s servisi durduruldu.", name.upper())
            except Exception:
                pass

        # Correlation Engine durdur
        if self.correlation is not None:
            try:
                self.correlation.stop()
            except Exception:
                pass

        # ThreatIntel kapat (GeoIP DB file handles)
        if self.threat_intel is not None:
            try:
                self.threat_intel.close()
            except Exception:
                pass

        # Sandbox motoru
        if self.sandbox_manager is not None:
            try:
                self.sandbox_manager.stop()
            except Exception as e:
                self.hp_logger.logger.debug("sandbox stop: %s", e)

        # Decoy konteynerlerini düşür
        self._compose_down()

        # PCAP durdur
        try:
            self.pcap.stop()
        except Exception:
            pass

        # Son raporu üret
        try:
            report_path = self.analyzer.generate_html_report()
            self.hp_logger.logger.info("Son rapor üretildi: %s", report_path)
        except Exception as e:
            self.hp_logger.logger.warning(
                "Son rapor üretilemedi: %s", str(e)
            )

        self.hp_logger.logger.info("Sistem durduruldu.")

    def _compose_up(self):
        """ftp + http decoy konteynerlerini docker compose ile build edip ayağa kaldır."""
        if not (self.config.get("docker") or {}).get("enabled", False):
            return
        compose_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml"
        )
        if not os.path.exists(compose_file):
            self.hp_logger.logger.warning(
                "docker-compose.yml bulunamadı: %s", compose_file
            )
            return
        try:
            self.hp_logger.logger.info("Decoy konteynerleri build ediliyor...")
            res = subprocess.run(
                ["docker", "compose", "-f", compose_file, "up", "-d", "--build"],
                capture_output=True, text=True, timeout=600,
            )
            if res.returncode != 0:
                self.hp_logger.logger.error(
                    "docker compose up başarısız: %s", res.stderr.strip()
                )
            else:
                self.hp_logger.logger.info("  ✓ Decoy konteynerleri ayakta")
        except FileNotFoundError:
            self.hp_logger.logger.error(
                "`docker` komutu bulunamadı — Docker yüklü mü?"
            )
        except subprocess.TimeoutExpired:
            self.hp_logger.logger.error("docker compose up zaman aşımına uğradı")
        except Exception as e:
            self.hp_logger.logger.error("compose_up hata: %s", e)

    def _compose_down(self):
        if not (self.config.get("docker") or {}).get("enabled", False):
            return
        compose_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml"
        )
        if not os.path.exists(compose_file):
            return
        try:
            subprocess.run(
                ["docker", "compose", "-f", compose_file, "down"],
                capture_output=True, text=True, timeout=60,
            )
        except Exception as e:
            self.hp_logger.logger.debug("compose_down: %s", e)

    def _start_periodic_tasks(self):
        """Periyodik görevler (rapor üretimi, temizlik)."""
        interval = self.config.get("analysis", {}).get(
            "auto_analyze_interval_sec", 300
        )

        def periodic():
            while self._running:
                time.sleep(interval)
                if not self._running:
                    break
                try:
                    self.alert_engine.cleanup_old_data()
                    self.analyzer.generate_html_report()
                    self.hp_logger.logger.debug(
                        "Periyodik analiz tamamlandı."
                    )
                except Exception as e:
                    self.hp_logger.logger.warning(
                        "Periyodik analiz hatası: %s", str(e)
                    )

        t = threading.Thread(target=periodic, name="periodic", daemon=True)
        t.start()


def main():
    parser = argparse.ArgumentParser(
        description="Honeypot Erken Uyarı Sistemi",
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Yapılandırma dosyası yolu (varsayılan: config.yaml)",
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Sadece rapor üret ve çık",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Dashboard olmadan başlat",
    )

    args = parser.parse_args()

    # Yapılandırmayı yükle
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), args.config
    )
    config = load_config(config_path)

    # Sadece rapor modu
    if args.report:
        hp_logger = HoneypotLogger(config)
        analyzer = Analyzer(config, hp_logger)
        report_path = analyzer.generate_html_report()
        print(f"Rapor oluşturuldu: {report_path}")
        return

    # Sistemi başlat
    system = HoneypotSystem(config, no_dashboard=args.no_dashboard)

    # Ctrl+C ile düzgün kapanma
    def signal_handler(sig, frame):
        print("\n[!] Kapatma sinyali alındı...")
        system.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    system.start()

    # Ana thread'i canlı tut
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        system.stop()


if __name__ == "__main__":
    main()
