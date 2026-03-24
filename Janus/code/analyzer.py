"""
Honeypot Erken Uyarı Sistemi - Analiz ve Raporlama Modülü
==========================================================
Toplanan logları analiz ederek:
- Saldırgan profilleri (IP, komutlar, izler)
- Saldırı zaman çizelgesi
- Kaba kuvvet / zararlı yazılım / yetki yükseltme istatistikleri
- Uygulanabilir erken uyarı raporu

üretir. HTML formatında detaylı rapor çıktısı verir.
"""

import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

from logger import HoneypotLogger


class Analyzer:
    """Log analizi ve rapor üretimi."""

    def __init__(self, config: dict, hp_logger: HoneypotLogger):
        self.hp_logger = hp_logger
        self.report_dir = config.get("general", {}).get(
            "report_directory", "reports"
        )
        os.makedirs(self.report_dir, exist_ok=True)

    def analyze(self) -> dict:
        """Tüm logları analiz et ve özet istatistik döndür."""
        events = self.hp_logger.read_events(last_n=10000)
        alerts = self.hp_logger.read_alerts(last_n=5000)
        commands = self.hp_logger.read_commands(last_n=5000)

        # --- Temel İstatistikler ---
        total_events = len(events)
        total_alerts = len(alerts)
        total_commands = len(commands)

        # --- IP Bazlı Analiz ---
        ip_counter = Counter(e.get("src_ip", "") for e in events)
        top_attackers = ip_counter.most_common(20)

        # --- Servis Bazlı Analiz ---
        service_counter = Counter(e.get("service", "") for e in events)

        # --- Olay Tipi Analiz ---
        event_type_counter = Counter(
            e.get("event_type", "") for e in events
        )

        # --- Alarm Tipi Analiz ---
        alert_type_counter = Counter(
            a.get("alert_type", "") for a in alerts
        )

        # --- Alarm Ciddiyet Analiz ---
        severity_counter = Counter(
            a.get("severity", "") for a in alerts
        )

        # --- Kimlik Doğrulama Analizi ---
        auth_events = [
            e for e in events if e.get("event_type") == "auth_attempt"
        ]
        unique_usernames = set()
        unique_passwords = set()
        for ae in auth_events:
            details = ae.get("details", {})
            if details.get("username"):
                unique_usernames.add(details["username"])
            if details.get("password"):
                unique_passwords.add(details["password"])

        username_counter = Counter(
            e.get("details", {}).get("username", "")
            for e in auth_events
        )

        # --- Komut Analizi ---
        cmd_counter = Counter(c.get("command", "") for c in commands)
        top_commands = cmd_counter.most_common(20)

        # --- Tehlikeli Komut Tespiti ---
        dangerous_keywords = [
            "sudo", "su ", "wget", "curl", "nc ", "bash -i",
            "python -c", "chmod", "/etc/passwd", "/etc/shadow",
            "nmap", "metasploit", "exploit",
        ]
        dangerous_commands = []
        for c in commands:
            cmd = c.get("command", "").lower()
            for kw in dangerous_keywords:
                if kw in cmd:
                    dangerous_commands.append(c)
                    break

        # --- Dosya Yükleme Analizi ---
        upload_events = [
            e for e in events if e.get("event_type") == "file_upload"
        ]

        # --- Zaman Serisi (saatlik) ---
        hourly_events = defaultdict(int)
        for e in events:
            ts = e.get("timestamp", "")
            if ts:
                try:
                    hour = ts[:13]  # "2024-01-15T14"
                    hourly_events[hour] += 1
                except Exception:
                    pass

        # --- Saldırı Zaman Çizelgesi ---
        timeline = []
        for a in alerts:
            timeline.append({
                "timestamp": a.get("timestamp", ""),
                "type": a.get("alert_type", ""),
                "severity": a.get("severity", ""),
                "ip": a.get("src_ip", ""),
                "description": a.get("description", ""),
            })

        analysis = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "total_commands": total_commands,
                "unique_ips": len(ip_counter),
                "unique_usernames": len(unique_usernames),
                "unique_passwords": len(unique_passwords),
                "file_uploads": len(upload_events),
                "dangerous_commands": len(dangerous_commands),
            },
            "top_attackers": [
                {"ip": ip, "count": cnt} for ip, cnt in top_attackers
            ],
            "service_distribution": dict(service_counter),
            "event_types": dict(event_type_counter),
            "alert_types": dict(alert_type_counter),
            "severity_distribution": dict(severity_counter),
            "top_usernames": [
                {"username": u, "count": c}
                for u, c in username_counter.most_common(20)
            ],
            "top_commands": [
                {"command": cmd, "count": cnt}
                for cmd, cnt in top_commands
            ],
            "dangerous_commands": dangerous_commands[:50],
            "file_uploads": [
                e.get("details", {}) for e in upload_events[:20]
            ],
            "hourly_activity": dict(sorted(hourly_events.items())),
            "attack_timeline": timeline[:100],
        }

        return analysis

    def generate_html_report(self) -> str:
        """HTML formatında detaylı analiz raporu üret."""
        analysis = self.analyze()
        summary = analysis["summary"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Honeypot Erken Uyarı Sistemi - Analiz Raporu</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a1a;
               color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; text-align: center; padding: 20px;
              border-bottom: 2px solid #00d4ff; margin-bottom: 30px; }}
        h2 {{ color: #ff6b6b; margin: 25px 0 15px 0; padding-bottom: 5px;
              border-bottom: 1px solid #333; }}
        h3 {{ color: #ffa500; margin: 15px 0 10px 0; }}

        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                       gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 10px;
                      text-align: center; border: 1px solid #333; }}
        .stat-card .number {{ font-size: 2.5em; font-weight: bold; color: #00d4ff; }}
        .stat-card .label {{ color: #aaa; margin-top: 5px; }}

        .severity-critical {{ color: #ff0000; font-weight: bold; }}
        .severity-high {{ color: #ff6b6b; font-weight: bold; }}
        .severity-medium {{ color: #ffa500; }}
        .severity-low {{ color: #4CAF50; }}

        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: #1a1a2e; }}
        th {{ background: #16213e; color: #00d4ff; padding: 12px; text-align: left;
              border: 1px solid #333; }}
        td {{ padding: 10px 12px; border: 1px solid #333; }}
        tr:hover {{ background: #16213e; }}

        .alert-box {{ background: #2d1b1b; border-left: 4px solid #ff0000;
                      padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .warning-box {{ background: #2d2b1b; border-left: 4px solid #ffa500;
                        padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .info-box {{ background: #1b2d2d; border-left: 4px solid #00d4ff;
                     padding: 15px; margin: 10px 0; border-radius: 5px; }}

        .timeline {{ position: relative; padding: 10px 0; }}
        .timeline-item {{ padding: 10px 20px; border-left: 3px solid #00d4ff;
                          margin-left: 20px; margin-bottom: 10px; background: #1a1a2e;
                          border-radius: 0 5px 5px 0; }}

        .footer {{ text-align: center; padding: 30px; color: #666;
                   border-top: 1px solid #333; margin-top: 40px; }}

        code {{ background: #0a0a1a; padding: 2px 6px; border-radius: 3px;
               font-family: 'Consolas', monospace; color: #00ff88; }}
    </style>
</head>
<body>
<div class="container">

<h1>🛡️ Honeypot Erken Uyarı Sistemi - Analiz Raporu</h1>
<p style="text-align:center; color:#888;">Rapor Tarihi: {analysis['generated_at']}</p>

<!-- ===== ÖZET İSTATİSTİKLER ===== -->
<h2>📊 Özet İstatistikler</h2>
<div class="stats-grid">
    <div class="stat-card">
        <div class="number">{summary['total_events']}</div>
        <div class="label">Toplam Olay</div>
    </div>
    <div class="stat-card">
        <div class="number" style="color:#ff6b6b">{summary['total_alerts']}</div>
        <div class="label">Toplam Alarm</div>
    </div>
    <div class="stat-card">
        <div class="number">{summary['unique_ips']}</div>
        <div class="label">Benzersiz IP</div>
    </div>
    <div class="stat-card">
        <div class="number">{summary['total_commands']}</div>
        <div class="label">Çalıştırılan Komut</div>
    </div>
    <div class="stat-card">
        <div class="number">{summary['unique_usernames']}</div>
        <div class="label">Denenen Kullanıcı Adı</div>
    </div>
    <div class="stat-card">
        <div class="number">{summary['unique_passwords']}</div>
        <div class="label">Denenen Şifre</div>
    </div>
    <div class="stat-card">
        <div class="number" style="color:#ff0000">{summary['file_uploads']}</div>
        <div class="label">Dosya Yükleme</div>
    </div>
    <div class="stat-card">
        <div class="number" style="color:#ff0000">{summary['dangerous_commands']}</div>
        <div class="label">Tehlikeli Komut</div>
    </div>
</div>

<!-- ===== ALARM DAĞILIMI ===== -->
<h2>🚨 Alarm Dağılımı</h2>
<div class="stats-grid">
"""
        severity_colors = {
            "critical": "#ff0000", "high": "#ff6b6b",
            "medium": "#ffa500", "low": "#4CAF50",
        }
        for sev, count in analysis["severity_distribution"].items():
            color = severity_colors.get(sev, "#888")
            html += f"""    <div class="stat-card">
        <div class="number" style="color:{color}">{count}</div>
        <div class="label">{sev.upper()}</div>
    </div>\n"""

        html += """</div>

<table>
<tr><th>Alarm Tipi</th><th>Sayı</th></tr>
"""
        for atype, count in sorted(
            analysis["alert_types"].items(), key=lambda x: x[1], reverse=True
        ):
            html += f"<tr><td>{atype}</td><td>{count}</td></tr>\n"

        html += """</table>

<!-- ===== EN AKTİF SALDIRANLAR ===== -->
<h2>🎯 En Aktif Saldırgan IP Adresleri</h2>
<table>
<tr><th>Sıra</th><th>IP Adresi</th><th>Olay Sayısı</th></tr>
"""
        for i, attacker in enumerate(analysis["top_attackers"][:15], 1):
            html += (
                f"<tr><td>{i}</td><td><code>{attacker['ip']}</code></td>"
                f"<td>{attacker['count']}</td></tr>\n"
            )

        html += """</table>

<!-- ===== KİMLİK DOĞRULAMA ANALİZİ ===== -->
<h2>🔑 Kimlik Doğrulama Analizi</h2>
<h3>En Çok Denenen Kullanıcı Adları</h3>
<table>
<tr><th>Kullanıcı Adı</th><th>Deneme Sayısı</th></tr>
"""
        for entry in analysis["top_usernames"][:15]:
            html += (
                f"<tr><td><code>{entry['username']}</code></td>"
                f"<td>{entry['count']}</td></tr>\n"
            )

        html += """</table>

<!-- ===== KOMUT ANALİZİ ===== -->
<h2>💻 Saldırgan Komut Analizi</h2>
<h3>En Sık Çalıştırılan Komutlar</h3>
<table>
<tr><th>Komut</th><th>Sayı</th></tr>
"""
        for entry in analysis["top_commands"][:20]:
            safe_cmd = entry["command"].replace("<", "&lt;").replace(">", "&gt;")
            html += (
                f"<tr><td><code>{safe_cmd}</code></td>"
                f"<td>{entry['count']}</td></tr>\n"
            )

        html += """</table>

<!-- ===== TEHLİKELİ KOMUTLAR ===== -->
<h2>⚠️ Tehlikeli Komutlar</h2>
"""
        if analysis["dangerous_commands"]:
            html += "<table>\n<tr><th>Zaman</th><th>IP</th><th>Servis</th><th>Komut</th></tr>\n"
            for dc in analysis["dangerous_commands"][:30]:
                safe_cmd = dc.get("command", "").replace("<", "&lt;").replace(">", "&gt;")
                html += (
                    f"<tr><td>{dc.get('timestamp', '')[:19]}</td>"
                    f"<td><code>{dc.get('src_ip', '')}</code></td>"
                    f"<td>{dc.get('service', '')}</td>"
                    f"<td><code>{safe_cmd}</code></td></tr>\n"
                )
            html += "</table>\n"
        else:
            html += '<div class="info-box">Tehlikeli komut tespit edilmedi.</div>\n'

        # ===== DOSYA YÜKLEMELERİ =====
        html += """
<h2>📁 Dosya Yükleme Girişimleri</h2>
"""
        if analysis["file_uploads"]:
            html += "<table>\n<tr><th>Dosya Yolu</th><th>Boyut (byte)</th><th>SHA-256</th></tr>\n"
            for fu in analysis["file_uploads"]:
                html += (
                    f"<tr><td><code>{fu.get('filepath', '')}</code></td>"
                    f"<td>{fu.get('size', 0)}</td>"
                    f"<td><code>{fu.get('sha256', '')[:16]}...</code></td></tr>\n"
                )
            html += "</table>\n"
        else:
            html += '<div class="info-box">Dosya yükleme girişimi tespit edilmedi.</div>\n'

        # ===== SALDIRI ZAMAN ÇİZELGESİ =====
        html += """
<h2>📅 Saldırı Zaman Çizelgesi</h2>
<div class="timeline">
"""
        for item in analysis["attack_timeline"][:30]:
            sev = item.get("severity", "low")
            sev_class = f"severity-{sev}"
            html += f"""    <div class="timeline-item">
        <strong class="{sev_class}">[{sev.upper()}]</strong>
        <span style="color:#888;">{item.get('timestamp', '')[:19]}</span><br>
        <strong>{item.get('type', '')}</strong> - {item.get('ip', '')}<br>
        {item.get('description', '')}
    </div>\n"""

        html += """</div>

<!-- ===== SERVİS DAĞILIMI ===== -->
<h2>🌐 Servis Dağılımı</h2>
<table>
<tr><th>Servis</th><th>Olay Sayısı</th></tr>
"""
        for svc, count in sorted(
            analysis["service_distribution"].items(),
            key=lambda x: x[1], reverse=True,
        ):
            html += f"<tr><td>{svc.upper()}</td><td>{count}</td></tr>\n"

        html += """</table>

<!-- ===== ÖNERİLER ===== -->
<h2>📋 Erken Uyarı Önerileri</h2>
"""
        recommendations = self._generate_recommendations(analysis)
        for rec in recommendations:
            box_class = "alert-box" if rec["priority"] == "high" else (
                "warning-box" if rec["priority"] == "medium" else "info-box"
            )
            html += f"""<div class="{box_class}">
    <strong>{rec['title']}</strong><br>
    {rec['description']}
</div>\n"""

        html += f"""
<div class="footer">
    <p>Honeypot Erken Uyarı Sistemi - Otomatik Analiz Raporu</p>
    <p>Rapor Tarihi: {analysis['generated_at']}</p>
    <p>Bu rapor, izole simülasyon ortamında toplanan verilere dayanmaktadır.</p>
</div>

</div>
</body>
</html>"""

        # Raporu dosyaya kaydet
        report_path = os.path.join(
            self.report_dir, f"honeypot_report_{timestamp}.html"
        )
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        # JSON analizini de kaydet
        json_path = os.path.join(
            self.report_dir, f"honeypot_analysis_{timestamp}.json"
        )
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(analysis, f, ensure_ascii=False, indent=2)

        self.hp_logger.logger.info("Rapor oluşturuldu: %s", report_path)
        return report_path

    @staticmethod
    def _generate_recommendations(analysis: dict) -> list:
        """Analiz sonuçlarına göre erken uyarı önerileri üret."""
        recs = []
        summary = analysis["summary"]
        alert_types = analysis.get("alert_types", {})

        if alert_types.get("brute_force", 0) > 0:
            recs.append({
                "priority": "high",
                "title": "🔴 Kaba Kuvvet Saldırısı Tespit Edildi",
                "description": (
                    f"Toplam {alert_types['brute_force']} kaba kuvvet alarmı "
                    f"üretildi. Öneriler: (1) SSH/FTP portlarını standart dışı "
                    f"portlara taşıyın, (2) fail2ban veya benzeri IP engelleme "
                    f"mekanizması kurun, (3) Çok faktörlü kimlik doğrulama (MFA) "
                    f"etkinleştirin, (4) Parola politikasını güçlendirin."
                ),
            })

        if alert_types.get("malware_upload", 0) > 0:
            recs.append({
                "priority": "high",
                "title": "🔴 Zararlı Yazılım Yükleme Girişimi",
                "description": (
                    f"{alert_types['malware_upload']} dosya yükleme alarmı. "
                    f"Öneriler: (1) FTP yazma izinlerini kısıtlayın, "
                    f"(2) Dosya yükleme dizinlerini noexec olarak mount edin, "
                    f"(3) Antivirüs/EDR çözümü entegre edin, "
                    f"(4) Yüklenen dosyaların SHA-256 hash'lerini tehdit "
                    f"istihbaratıyla karşılaştırın."
                ),
            })

        if alert_types.get("privilege_escalation", 0) > 0:
            recs.append({
                "priority": "high",
                "title": "🔴 Yetki Yükseltme Girişimi",
                "description": (
                    f"{alert_types['privilege_escalation']} yetki yükseltme "
                    f"alarmı. Öneriler: (1) sudo yetkilerini en az ayrıcalık "
                    f"ilkesine göre yapılandırın, (2) SUID/SGID dosyalarını "
                    f"düzenli denetleyin, (3) Kernel ve yazılım güncellemelerini "
                    f"yapın, (4) SELinux/AppArmor politikalarını etkinleştirin."
                ),
            })

        if alert_types.get("sql_injection", 0) > 0:
            recs.append({
                "priority": "high",
                "title": "🔴 SQL Injection Saldırısı",
                "description": (
                    f"SQL injection denemeleri tespit edildi. "
                    f"Öneriler: (1) Parametreli sorgular (prepared statements) "
                    f"kullanın, (2) Web Application Firewall (WAF) kurun, "
                    f"(3) Veritabanı kullanıcı yetkilerini kısıtlayın."
                ),
            })

        if alert_types.get("port_scan", 0) > 0:
            recs.append({
                "priority": "medium",
                "title": "🟠 Port Tarama Tespit Edildi",
                "description": (
                    f"Ağ keşif (port tarama) etkinliği tespit edildi. "
                    f"Öneriler: (1) Gereksiz portları kapatın, "
                    f"(2) Firewall kurallarını sıkılaştırın, "
                    f"(3) IDS/IPS sistemlerini etkinleştirin."
                ),
            })

        if summary["unique_ips"] > 0:
            recs.append({
                "priority": "medium",
                "title": f"🟠 {summary['unique_ips']} Benzersiz Saldırgan IP",
                "description": (
                    f"Honeypot'a {summary['unique_ips']} farklı IP adresinden "
                    f"erişim yapıldı. En aktif IP'ler izlenmeli ve "
                    f"gerekirse engelleme listesine eklenmelidir. "
                    f"Tekrarlayan IP'ler için tehdit istihbaratı sorgusu yapılmalıdır."
                ),
            })

        if not recs:
            recs.append({
                "priority": "low",
                "title": "✅ Henüz Kritik Bulgu Yok",
                "description": (
                    "Şu ana kadar kritik bir saldırı bulgusu tespit edilmedi. "
                    "Honeypot izlemeye devam ediyor."
                ),
            })

        return recs
