"""
Honeypot Erken Uyarı Sistemi - Web Dashboard
=============================================
Flask tabanlı gerçek zamanlı izleme paneli.
Alarm, olay ve analiz verilerini görselleştirir.
"""

import json
import threading
import time
import os
from datetime import datetime

try:
    from flask import Flask, render_template_string, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from logger import HoneypotLogger
from analyzer import Analyzer
from alert_engine import AlertEngine


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Honeypot Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0a0a1a; color: #e0e0e0;
        }
        .header {
            background: linear-gradient(135deg, #0f3460, #16213e);
            padding: 15px 30px; display: flex; align-items: center;
            justify-content: space-between; border-bottom: 2px solid #00d4ff;
        }
        .header h1 { color: #00d4ff; font-size: 1.4em; }
        .header .status { color: #00ff88; font-size: 0.9em; }

        .main { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;
                 padding: 20px; }

        .card { background: #1a1a2e; border-radius: 10px; padding: 20px;
                border: 1px solid #333; }
        .card h3 { color: #00d4ff; margin-bottom: 15px; font-size: 1.1em; }

        .stat-row { display: flex; justify-content: space-between;
                    padding: 8px 0; border-bottom: 1px solid #222; }
        .stat-row .label { color: #aaa; }
        .stat-row .value { font-weight: bold; }

        .big-number { font-size: 2.5em; font-weight: bold; text-align: center;
                      padding: 10px; }

        .alert-item {
            padding: 10px; margin: 5px 0; border-radius: 5px;
            border-left: 4px solid; font-size: 0.85em;
        }
        .alert-critical { border-color: #ff0000; background: #2d1b1b; }
        .alert-high { border-color: #ff6b6b; background: #2d1f1f; }
        .alert-medium { border-color: #ffa500; background: #2d2b1b; }
        .alert-low { border-color: #4CAF50; background: #1b2d1b; }

        .event-item {
            padding: 6px 10px; margin: 3px 0; background: #111;
            border-radius: 3px; font-size: 0.8em; font-family: monospace;
        }

        .full-width { grid-column: 1 / -1; }
        .two-cols { grid-column: span 2; }

        .refresh-btn {
            background: #0f3460; color: #00d4ff; border: 1px solid #00d4ff;
            padding: 8px 16px; border-radius: 5px; cursor: pointer;
        }
        .refresh-btn:hover { background: #16213e; }

        .severity-critical { color: #ff0000; }
        .severity-high { color: #ff6b6b; }
        .severity-medium { color: #ffa500; }
        .severity-low { color: #4CAF50; }

        #auto-refresh { margin-left: 10px; }

        table { width: 100%; border-collapse: collapse; }
        th { background: #0f3460; color: #00d4ff; padding: 8px;
             text-align: left; }
        td { padding: 6px 8px; border-bottom: 1px solid #222;
             font-size: 0.85em; }

        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
        .live-dot { display: inline-block; width: 8px; height: 8px;
                    background: #00ff88; border-radius: 50%;
                    margin-right: 5px; animation: pulse 2s infinite; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Honeypot Erken Uyarı Sistemi</h1>
        <div>
            <span class="status"><span class="live-dot"></span>CANLI</span>
            <button class="refresh-btn" onclick="refreshAll()">🔄 Yenile</button>
            <label id="auto-refresh">
                <input type="checkbox" id="autoRefresh" checked onchange="toggleAutoRefresh()">
                Otomatik (5s)
            </label>
        </div>
    </div>

    <div class="main">
        <!-- Özet Kartları -->
        <div class="card">
            <h3>📊 Toplam Olay</h3>
            <div class="big-number" id="totalEvents" style="color:#00d4ff;">-</div>
        </div>
        <div class="card">
            <h3>🚨 Toplam Alarm</h3>
            <div class="big-number" id="totalAlerts" style="color:#ff6b6b;">-</div>
        </div>
        <div class="card">
            <h3>💻 Toplam Komut</h3>
            <div class="big-number" id="totalCommands" style="color:#ffa500;">-</div>
        </div>

        <!-- Son Alarmlar -->
        <div class="card two-cols">
            <h3>🚨 Son Alarmlar</h3>
            <div id="alertsList">Yükleniyor...</div>
        </div>

        <!-- Alarm İstatistikleri -->
        <div class="card">
            <h3>📈 Alarm Dağılımı</h3>
            <div id="alertStats">Yükleniyor...</div>
        </div>

        <!-- Son Olaylar -->
        <div class="card two-cols">
            <h3>📋 Son Olaylar</h3>
            <div id="eventsList" style="max-height:400px;overflow-y:auto;">
                Yükleniyor...
            </div>
        </div>

        <!-- En Aktif IP'ler -->
        <div class="card">
            <h3>🎯 En Aktif IP'ler</h3>
            <div id="topIPs">Yükleniyor...</div>
        </div>

        <!-- Son Komutlar -->
        <div class="card full-width">
            <h3>💻 Son Çalıştırılan Komutlar</h3>
            <div id="commandsList" style="max-height:300px;overflow-y:auto;">
                Yükleniyor...
            </div>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;

        async function fetchJSON(url) {
            const r = await fetch(url);
            return r.json();
        }

        async function refreshAll() {
            try {
                // Özet
                const stats = await fetchJSON('/api/stats');
                document.getElementById('totalEvents').textContent = stats.total_events || 0;
                document.getElementById('totalAlerts').textContent = stats.total_alerts || 0;
                document.getElementById('totalCommands').textContent = stats.total_commands || 0;

                // Son Alarmlar
                const alerts = await fetchJSON('/api/alerts?n=15');
                const alertsDiv = document.getElementById('alertsList');
                if (alerts.length === 0) {
                    alertsDiv.innerHTML = '<p style="color:#666;">Henüz alarm yok</p>';
                } else {
                    alertsDiv.innerHTML = alerts.reverse().map(a =>
                        `<div class="alert-item alert-${a.severity}">
                            <strong class="severity-${a.severity}">[${(a.severity||'').toUpperCase()}]</strong>
                            <span style="color:#888;">${(a.timestamp||'').substring(0,19)}</span><br>
                            <strong>${a.alert_type}</strong> — ${a.src_ip}<br>
                            ${a.description}
                        </div>`
                    ).join('');
                }

                // Alarm İstatistikleri
                const alertStats = await fetchJSON('/api/alert_stats');
                const statsDiv = document.getElementById('alertStats');
                statsDiv.innerHTML = Object.entries(alertStats).map(([k,v]) =>
                    `<div class="stat-row">
                        <span class="label">${k}</span>
                        <span class="value">${v}</span>
                    </div>`
                ).join('');

                // Son Olaylar
                const events = await fetchJSON('/api/events?n=20');
                const eventsDiv = document.getElementById('eventsList');
                if (events.length === 0) {
                    eventsDiv.innerHTML = '<p style="color:#666;">Henüz olay yok</p>';
                } else {
                    eventsDiv.innerHTML = events.reverse().map(e =>
                        `<div class="event-item">
                            <span style="color:#888;">${(e.timestamp||'').substring(11,19)}</span>
                            <span style="color:#00d4ff;">[${(e.service||'').toUpperCase()}]</span>
                            <strong>${e.event_type}</strong>
                            — ${e.src_ip}:${e.src_port}
                            ${e.details ? ' | ' + JSON.stringify(e.details).substring(0,80) : ''}
                        </div>`
                    ).join('');
                }

                // En Aktif IP'ler
                const topIPs = await fetchJSON('/api/top_ips');
                const ipsDiv = document.getElementById('topIPs');
                if (topIPs.length === 0) {
                    ipsDiv.innerHTML = '<p style="color:#666;">Veri yok</p>';
                } else {
                    ipsDiv.innerHTML = '<table><tr><th>IP</th><th>Olay</th></tr>' +
                        topIPs.map(ip =>
                            `<tr><td>${ip.ip}</td><td>${ip.count}</td></tr>`
                        ).join('') + '</table>';
                }

                // Son Komutlar
                const cmds = await fetchJSON('/api/commands?n=15');
                const cmdsDiv = document.getElementById('commandsList');
                if (cmds.length === 0) {
                    cmdsDiv.innerHTML = '<p style="color:#666;">Henüz komut yok</p>';
                } else {
                    cmdsDiv.innerHTML = cmds.reverse().map(c =>
                        `<div class="event-item">
                            <span style="color:#888;">${(c.timestamp||'').substring(11,19)}</span>
                            <span style="color:#ffa500;">[${(c.service||'').toUpperCase()}]</span>
                            ${c.src_ip} ▸ <strong style="color:#00ff88;">${
                                c.command.replace(/</g,'&lt;').replace(/>/g,'&gt;')
                            }</strong>
                        </div>`
                    ).join('');
                }
            } catch(e) {
                console.error('Refresh error:', e);
            }
        }

        function toggleAutoRefresh() {
            if (document.getElementById('autoRefresh').checked) {
                autoRefreshInterval = setInterval(refreshAll, 5000);
            } else {
                clearInterval(autoRefreshInterval);
            }
        }

        // İlk yükleme
        refreshAll();
        autoRefreshInterval = setInterval(refreshAll, 5000);
    </script>
</body>
</html>"""


class Dashboard:
    """Flask tabanlı web dashboard."""

    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_engine: AlertEngine, analyzer: Analyzer):
        if not FLASK_AVAILABLE:
            hp_logger.logger.warning(
                "Flask kurulamadı - Dashboard devre dışı. "
                "Kurulum: pip install flask"
            )
            self.enabled = False
            return

        dash_cfg = config.get("dashboard", {})
        self.enabled = dash_cfg.get("enabled", True)
        self.host = dash_cfg.get("bind_host", "127.0.0.1")
        self.port = dash_cfg.get("bind_port", 5000)

        self.hp_logger = hp_logger
        self.alert_engine = alert_engine
        self.analyzer = analyzer

        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        app = self.app

        @app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route("/api/stats")
        def api_stats():
            events = self.hp_logger.read_events(last_n=10000)
            alerts = self.hp_logger.read_alerts(last_n=5000)
            commands = self.hp_logger.read_commands(last_n=5000)
            from collections import Counter
            ip_counter = Counter(e.get("src_ip", "") for e in events)
            return jsonify({
                "total_events": len(events),
                "total_alerts": len(alerts),
                "total_commands": len(commands),
                "unique_ips": len(ip_counter),
            })

        @app.route("/api/alerts")
        def api_alerts():
            from flask import request
            n = min(int(request.args.get("n", 20)), 200)
            return jsonify(self.hp_logger.read_alerts(last_n=n))

        @app.route("/api/events")
        def api_events():
            from flask import request
            n = min(int(request.args.get("n", 30)), 200)
            return jsonify(self.hp_logger.read_events(last_n=n))

        @app.route("/api/commands")
        def api_commands():
            from flask import request
            n = min(int(request.args.get("n", 20)), 200)
            return jsonify(self.hp_logger.read_commands(last_n=n))

        @app.route("/api/alert_stats")
        def api_alert_stats():
            return jsonify(self.alert_engine.get_stats())

        @app.route("/api/top_ips")
        def api_top_ips():
            events = self.hp_logger.read_events(last_n=10000)
            from collections import Counter
            ip_counter = Counter(e.get("src_ip", "") for e in events)
            return jsonify([
                {"ip": ip, "count": cnt}
                for ip, cnt in ip_counter.most_common(15)
            ])

        @app.route("/api/report")
        def api_report():
            path = self.analyzer.generate_html_report()
            return jsonify({"status": "ok", "report_path": path})

    def start(self):
        if not self.enabled:
            return

        import logging as stdlib_logging
        log = stdlib_logging.getLogger('werkzeug')
        log.setLevel(stdlib_logging.WARNING)

        self.hp_logger.logger.info(
            "Dashboard başlatılıyor: http://%s:%d", self.host, self.port
        )
        thread = threading.Thread(
            target=lambda: self.app.run(
                host=self.host, port=self.port, debug=False,
                use_reloader=False,
            ),
            name="dashboard",
            daemon=True,
        )
        thread.start()

    def stop(self):
        pass  # Flask daemon thread olarak kapanır
