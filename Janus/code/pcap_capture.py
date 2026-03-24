"""
Honeypot Erken Uyarı Sistemi - PCAP Ağ Trafiği Yakalama Modülü
===============================================================
Honeypot servislerine yönelik tüm ağ trafiğini PCAP formatında
kaydeder. Wireshark ve tcpdump ile uyumlu çıktı üretir.

Scapy kütüphanesi ile paket yakalama ve kayıt.
"""

import os
import time
import threading
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from logger import HoneypotLogger


class PcapCapture:
    """
    Ağ trafiği yakalama sınıfı.
    Honeypot portlarına gelen trafiği PCAP dosyalarına kaydeder.
    """

    def __init__(self, config: dict, hp_logger: HoneypotLogger):
        pcap_cfg = config.get("pcap", {})
        self.enabled = pcap_cfg.get("enabled", True)
        self.interface = pcap_cfg.get("interface", "auto")
        self.capture_filter = pcap_cfg.get("capture_filter", "")
        self.max_file_size_mb = pcap_cfg.get("max_file_size_mb", 100)
        self.rotation_count = pcap_cfg.get("rotation_count", 10)

        self.pcap_dir = config.get("general", {}).get(
            "pcap_directory", "captures"
        )
        os.makedirs(self.pcap_dir, exist_ok=True)

        # Honeypot portlarını topla (BPF filtresi için)
        services = config.get("services", {})
        self.honeypot_ports = []
        for svc_name, svc_cfg in services.items():
            if svc_cfg.get("enabled", False):
                port = svc_cfg.get("bind_port")
                if port:
                    self.honeypot_ports.append(port)

        self.hp_logger = hp_logger
        self._running = False
        self._packets = []
        self._packet_lock = threading.Lock()
        self._current_file_index = 0

    def start(self):
        """PCAP yakalamayı başlat."""
        if not self.enabled:
            self.hp_logger.logger.info("PCAP yakalama devre dışı.")
            return

        if not SCAPY_AVAILABLE:
            self.hp_logger.logger.warning(
                "Scapy kurulamadı - PCAP yakalama devre dışı. "
                "Kurulum: pip install scapy"
            )
            # Scapy yoksa basit soket tabanlı yakalamaya geç
            self._start_simple_capture()
            return

        self._running = True

        # BPF filtresi oluştur
        if self.capture_filter:
            bpf = self.capture_filter
        elif self.honeypot_ports:
            port_filters = " or ".join(
                f"port {p}" for p in self.honeypot_ports
            )
            bpf = f"tcp and ({port_filters})"
        else:
            bpf = ""

        self.hp_logger.logger.info(
            "PCAP yakalama başlatılıyor | Filtre: %s | Dizin: %s",
            bpf or "(tümü)", self.pcap_dir,
        )

        # Yakalama thread'i
        thread = threading.Thread(
            target=self._capture_loop,
            args=(bpf,),
            name="pcap-capture",
            daemon=True,
        )
        thread.start()

        # Periyodik dosyaya yazma thread'i
        writer = threading.Thread(
            target=self._periodic_writer,
            name="pcap-writer",
            daemon=True,
        )
        writer.start()

    def stop(self):
        """Yakalamayı durdur ve kalan paketleri kaydet."""
        self._running = False
        self._flush_packets()

    def _capture_loop(self, bpf: str):
        """Scapy ile paket yakalama döngüsü."""
        try:
            iface = None if self.interface == "auto" else self.interface
            sniff(
                iface=iface,
                filter=bpf if bpf else None,
                prn=self._packet_callback,
                stop_filter=lambda _: not self._running,
                store=False,
            )
        except PermissionError:
            self.hp_logger.logger.error(
                "PCAP yakalama için yönetici/root yetkisi gerekli!"
            )
        except Exception as e:
            self.hp_logger.logger.error("PCAP yakalama hatası: %s", str(e))

    def _packet_callback(self, packet):
        """Her yakalanan paket için çağrılır."""
        with self._packet_lock:
            self._packets.append(packet)

    def _periodic_writer(self):
        """Her 30 saniyede paketleri dosyaya yaz."""
        while self._running:
            time.sleep(30)
            self._flush_packets()

    def _flush_packets(self):
        """Bellekteki paketleri PCAP dosyasına yaz."""
        with self._packet_lock:
            if not self._packets:
                return
            packets_to_write = list(self._packets)
            self._packets.clear()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"honeypot_{timestamp}.pcap"
        filepath = os.path.join(self.pcap_dir, filename)

        try:
            wrpcap(filepath, packets_to_write)
            self.hp_logger.logger.info(
                "PCAP kaydedildi: %s (%d paket)",
                filepath, len(packets_to_write),
            )
        except Exception as e:
            self.hp_logger.logger.error(
                "PCAP yazma hatası: %s", str(e)
            )

        # Dosya rotasyonu
        self._rotate_files()

    def _rotate_files(self):
        """Eski PCAP dosyalarını temizle."""
        try:
            files = sorted(
                [
                    os.path.join(self.pcap_dir, f)
                    for f in os.listdir(self.pcap_dir)
                    if f.endswith(".pcap")
                ],
                key=lambda x: os.path.getmtime(x),
            )
            while len(files) > self.rotation_count:
                oldest = files.pop(0)
                os.remove(oldest)
                self.hp_logger.logger.debug(
                    "Eski PCAP silindi: %s", oldest
                )
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Scapy olmadan basit PCAP alternatifi
    # ------------------------------------------------------------------ #

    def _start_simple_capture(self):
        """
        Scapy yoksa, her servisten gelen ham veriyi
        basit bir formatta kaydet (tam PCAP değil, metin tabanlı log).
        """
        self._running = True
        self.hp_logger.logger.info(
            "Basit trafik kaydı başlatıldı (Scapy yok, metin tabanlı)."
        )
        # Bu durumda loglar zaten honeypot_events.jsonl'de tutulur.
        # Ek bir thread'e gerek yok, her servis zaten loglama yapıyor.

    def get_capture_stats(self) -> dict:
        """Yakalama istatistikleri."""
        pcap_files = [
            f for f in os.listdir(self.pcap_dir) if f.endswith(".pcap")
        ] if os.path.exists(self.pcap_dir) else []

        total_size = sum(
            os.path.getsize(os.path.join(self.pcap_dir, f))
            for f in pcap_files
        )

        return {
            "enabled": self.enabled,
            "scapy_available": SCAPY_AVAILABLE,
            "pcap_files": len(pcap_files),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "pcap_directory": self.pcap_dir,
            "monitored_ports": self.honeypot_ports,
        }
