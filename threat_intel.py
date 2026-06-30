"""
Threat Intelligence & GeoIP Enrichment
=======================================
Her IP için:
  - MaxMind GeoLite2 → ülke, şehir, ASN, ISP
  - AbuseIPDB API    → itibar skoru, raporlama sayısı
  - Shodan API       → açık portlar, banner, servisler

Sonuçlar TTL-based bellek cache'inde tutulur; aynı IP için
yapılandırılabilir süre boyunca API'ye tekrar gidilmez.

Tüm API anahtarları config.yaml → threat_intel altında tanımlanır.
Eksik anahtar/kütüphane → o kaynak sessizce atlanır, diğerleri çalışır.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger("honeypot.threat_intel")

# ------------------------------------------------------------------ #
#  Opsiyonel bağımlılıklar
# ------------------------------------------------------------------ #
try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_OK = True
except ImportError:
    _GEOIP2_OK = False

try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False


# ------------------------------------------------------------------ #
#  Yardımcı: basit TTL cache
# ------------------------------------------------------------------ #
class _TTLCache:
    def __init__(self, ttl_sec: int = 3600):
        self._store: dict[str, tuple[float, Any]] = {}
        self._ttl = ttl_sec
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if entry and time.time() - entry[0] < self._ttl:
                return entry[1]
            return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._store[key] = (time.time(), value)

    def evict_expired(self):
        now = time.time()
        with self._lock:
            expired = [k for k, (ts, _) in self._store.items()
                       if now - ts >= self._ttl]
            for k in expired:
                del self._store[k]


# ------------------------------------------------------------------ #
#  GeoIP (MaxMind GeoLite2)
# ------------------------------------------------------------------ #
class GeoIPResolver:
    """
    Ücretsiz GeoLite2 veritabanı ile yerel coğrafi çözümleme.

    Kurulum:
      pip install geoip2
    Veritabanı: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    config.yaml → threat_intel.geoip.db_path: "GeoLite2-City.mmdb"
    """

    def __init__(self, db_city: str = "", db_asn: str = ""):
        self._city_reader = None
        self._asn_reader = None
        self._lock = threading.Lock()

        if not _GEOIP2_OK:
            logger.warning("geoip2 kütüphanesi yok — GeoIP devre dışı. "
                           "pip install geoip2")
            return

        if db_city:
            try:
                self._city_reader = geoip2.database.Reader(db_city)
                logger.info("GeoIP City DB yüklendi: %s", db_city)
            except Exception as e:
                logger.warning("GeoIP City DB açılamadı: %s", e)

        if db_asn:
            try:
                self._asn_reader = geoip2.database.Reader(db_asn)
                logger.info("GeoIP ASN DB yüklendi: %s", db_asn)
            except Exception as e:
                logger.warning("GeoIP ASN DB açılamadı: %s", e)

    def lookup(self, ip: str) -> dict:
        result: dict = {}
        if not _GEOIP2_OK:
            return result

        # RFC-1918 / loopback atla
        if ip.startswith(("10.", "192.168.", "172.", "127.", "::1")):
            return {"country": "Private", "city": "LAN", "asn": "", "isp": ""}

        with self._lock:
            if self._city_reader:
                try:
                    r = self._city_reader.city(ip)
                    result["country"] = r.country.name or ""
                    result["country_iso"] = r.country.iso_code or ""
                    result["city"] = r.city.name or ""
                    result["latitude"] = r.location.latitude
                    result["longitude"] = r.location.longitude
                    result["postal"] = r.postal.code or ""
                except Exception:
                    pass

            if self._asn_reader:
                try:
                    r = self._asn_reader.asn(ip)
                    result["asn"] = f"AS{r.autonomous_system_number}"
                    result["isp"] = r.autonomous_system_organization or ""
                except Exception:
                    pass

        return result

    def close(self):
        with self._lock:
            if self._city_reader:
                try:
                    self._city_reader.close()
                except Exception:
                    pass
            if self._asn_reader:
                try:
                    self._asn_reader.close()
                except Exception:
                    pass


# ------------------------------------------------------------------ #
#  AbuseIPDB
# ------------------------------------------------------------------ #
class AbuseIPDB:
    """
    AbuseIPDB v2 API entegrasyonu.
    https://www.abuseipdb.com/api.html

    config.yaml → threat_intel.abuseipdb.api_key: "YOUR_KEY"
    """

    BASE = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str = "", timeout: int = 5):
        self._key = api_key
        self._timeout = timeout
        self._ok = bool(api_key) and _REQUESTS_OK
        if not _REQUESTS_OK:
            logger.warning("requests kütüphanesi yok — AbuseIPDB devre dışı. "
                           "pip install requests")

    def lookup(self, ip: str) -> dict:
        if not self._ok:
            return {}
        if ip.startswith(("10.", "192.168.", "172.", "127.", "::1")):
            return {"abuse_score": 0, "total_reports": 0, "is_tor": False}
        try:
            resp = _requests.get(
                self.BASE,
                headers={"Key": self._key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90,
                        "verbose": False},
                timeout=self._timeout,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "abuse_score": d.get("abuseConfidenceScore", 0),
                    "total_reports": d.get("totalReports", 0),
                    "last_reported": d.get("lastReportedAt", ""),
                    "is_tor": d.get("isTor", False),
                    "usage_type": d.get("usageType", ""),
                    "isp": d.get("isp", ""),
                    "domain": d.get("domain", ""),
                }
        except Exception as e:
            logger.debug("AbuseIPDB hata [%s]: %s", ip, e)
        return {}


# ------------------------------------------------------------------ #
#  Shodan
# ------------------------------------------------------------------ #
class ShodanLookup:
    """
    Shodan host API entegrasyonu.
    https://developer.shodan.io/api

    config.yaml → threat_intel.shodan.api_key: "YOUR_KEY"
    """

    def __init__(self, api_key: str = "", timeout: int = 8):
        self._key = api_key
        self._timeout = timeout
        self._ok = bool(api_key) and _REQUESTS_OK

    def lookup(self, ip: str) -> dict:
        if not self._ok:
            return {}
        if ip.startswith(("10.", "192.168.", "172.", "127.", "::1")):
            return {}
        try:
            resp = _requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self._key},
                timeout=self._timeout,
            )
            if resp.status_code == 200:
                d = resp.json()
                ports = d.get("ports", [])
                vulns = list(d.get("vulns", {}).keys())
                tags = d.get("tags", [])
                hostnames = d.get("hostnames", [])
                org = d.get("org", "")
                return {
                    "open_ports": ports,
                    "hostnames": hostnames,
                    "org": org,
                    "vulns": vulns,
                    "tags": tags,
                    "last_update": d.get("last_update", ""),
                }
        except Exception as e:
            logger.debug("Shodan hata [%s]: %s", ip, e)
        return {}


# ------------------------------------------------------------------ #
#  Ana ThreatIntel Servisi
# ------------------------------------------------------------------ #
class ThreatIntel:
    """
    GeoIP + AbuseIPDB + Shodan kombinasyonu.
    Tek çağrı noktası: enrich(ip) → birleşik dict döner.
    Sonuçlar TTL cache'inde saklanır.
    """

    def __init__(self, config: dict):
        ti_cfg = config.get("threat_intel", {})
        cache_ttl = ti_cfg.get("cache_ttl_sec", 3600)
        self._cache = _TTLCache(ttl_sec=cache_ttl)

        # GeoIP
        geo_cfg = ti_cfg.get("geoip", {})
        self._geo = GeoIPResolver(
            db_city=geo_cfg.get("city_db", ""),
            db_asn=geo_cfg.get("asn_db", ""),
        )

        # AbuseIPDB
        abuse_cfg = ti_cfg.get("abuseipdb", {})
        self._abuse = AbuseIPDB(
            api_key=abuse_cfg.get("api_key", ""),
            timeout=abuse_cfg.get("timeout_sec", 5),
        )

        # Shodan
        shodan_cfg = ti_cfg.get("shodan", {})
        self._shodan = ShodanLookup(
            api_key=shodan_cfg.get("api_key", ""),
            timeout=shodan_cfg.get("timeout_sec", 8),
        )

        self._enabled = ti_cfg.get("enabled", True)
        logger.info("ThreatIntel başlatıldı (cache_ttl=%ds)", cache_ttl)

    def enrich(self, ip: str) -> dict:
        """
        IP adresini GeoIP + AbuseIPDB + Shodan ile zenginleştir.
        Sonuç cache'de yoksa API'leri sorgular (thread-safe).
        """
        if not self._enabled:
            return {}

        cached = self._cache.get(ip)
        if cached is not None:
            return cached

        result: dict = {"ip": ip}

        # GeoIP (yerel, hızlı)
        geo = self._geo.lookup(ip)
        if geo:
            result["geo"] = geo

        # AbuseIPDB (API çağrısı)
        abuse = self._abuse.lookup(ip)
        if abuse:
            result["abuse"] = abuse
            # Yüksek skor → tehdit etiketi
            score = abuse.get("abuse_score", 0)
            if score >= 80:
                result["threat_level"] = "critical"
            elif score >= 50:
                result["threat_level"] = "high"
            elif score >= 20:
                result["threat_level"] = "medium"
            else:
                result["threat_level"] = "low"

        # Shodan (API çağrısı, en yavaş)
        shodan = self._shodan.lookup(ip)
        if shodan:
            result["shodan"] = shodan

        self._cache.set(ip, result)
        return result

    def enrich_alert(self, alert: dict) -> dict:
        """
        Mevcut bir alert dict'ine threat intel ekle.
        alert["threat_intel"] key'i olarak eklenir; orijinal değişmez.
        """
        ip = alert.get("src_ip", "")
        if not ip:
            return alert
        intel = self.enrich(ip)
        enriched = dict(alert)
        enriched["threat_intel"] = intel
        return enriched

    def summary_line(self, ip: str) -> str:
        """Tek satır özet: konsol logları için."""
        intel = self.enrich(ip)
        parts = []
        geo = intel.get("geo", {})
        if geo.get("country"):
            parts.append(f"{geo['country']}/{geo.get('city','?')}")
        if geo.get("asn"):
            parts.append(geo["asn"])
        abuse = intel.get("abuse", {})
        if abuse:
            parts.append(f"AbuseScore={abuse.get('abuse_score',0)}")
        shodan = intel.get("shodan", {})
        if shodan.get("open_ports"):
            parts.append(f"ports={shodan['open_ports'][:5]}")
        return " | ".join(parts) if parts else "no intel"

    def close(self):
        self._geo.close()
