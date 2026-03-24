"""
Honeypot Erken Uyarı Sistemi - HTTP Honeypot Modülü
====================================================
Sahte bir web sunucusu sunarak dizin tarama, SQL injection,
XSS, dosya keşfi ve yetkisiz erişim denemelerini kaydeder.

Socket tabanlı, sıfırdan kodlanmış HTTP protokol simülasyonu.
"""

import socket
import threading
import uuid
import json
import html
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote

from logger import HoneypotLogger


# ------------------------------------------------------------------ #
#  Sahte Web Sayfaları (HTML Şablonları)
# ------------------------------------------------------------------ #

LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Corp Admin Panel - Giriş</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; }}
        .login-box {{ background: #16213e; padding: 40px; border-radius: 10px;
                      box-shadow: 0 0 20px rgba(0,0,0,0.5); width: 350px; }}
        h2 {{ text-align: center; color: #0f3460; margin-bottom: 30px; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0 16px 0;
                border: 1px solid #0f3460; border-radius: 5px;
                background: #1a1a2e; color: #eee; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #e94560;
                 color: white; border: none; border-radius: 5px;
                 cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #c73e54; }}
        .footer {{ text-align: center; margin-top: 20px; font-size: 12px;
                   color: #666; }}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 Admin Panel</h2>
        <form method="POST" action="/admin/login">
            <label>Kullanıcı Adı</label>
            <input type="text" name="username" placeholder="admin" required>
            <label>Şifre</label>
            <input type="password" name="password" placeholder="••••••••" required>
            <button type="submit">Giriş Yap</button>
        </form>
        <div class="footer">Corp Server Management v3.2.1</div>
    </div>
</body>
</html>"""

LOGIN_FAILED_HTML = """<!DOCTYPE html>
<html><head><title>Giriş Başarısız</title>
<style>body{{font-family:Arial;background:#1a1a2e;color:#e94560;
text-align:center;padding-top:100px;}}</style>
</head><body>
<h2>❌ Giriş Başarısız</h2>
<p>Kullanıcı adı veya şifre hatalı.</p>
<a href="/admin/login" style="color:#0f3460;">Tekrar Dene</a>
</body></html>"""

NOT_FOUND_HTML = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.54 (Ubuntu) Server</address>
</body></html>"""

FAKE_API_RESPONSE = {
    "/api/v1/users": {
        "users": [
            {"id": 1, "username": "admin", "role": "administrator"},
            {"id": 2, "username": "operator", "role": "user"},
            {"id": 3, "username": "backup_svc", "role": "service"},
        ]
    },
    "/api/v1/config": {
        "database": {"host": "192.168.56.20", "port": 3306, "name": "corp_db"},
        "smtp": {"host": "mail.corp.local", "port": 25},
        "version": "3.2.1",
    },
}

FAKE_ENV_FILE = """APP_NAME=CorpServer
APP_ENV=production
APP_KEY=base64:aGVsbG93b3JsZHRoaXNpc2FmYWtla2V5
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=192.168.56.20
DB_PORT=3306
DB_DATABASE=corp_db
DB_USERNAME=root
DB_PASSWORD=MySQL_R00t_2024!
MAIL_HOST=mail.corp.local
"""

# Saldırı tespit desenleri
ATTACK_PATTERNS = [
    (r"(?:union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|"
     r"update\s+.*\s+set|delete\s+from|or\s+1\s*=\s*1|'\s*or\s*'|"
     r"--\s*$|;\s*drop)", "sql_injection"),
    (r"(?:<script|javascript:|onerror\s*=|onload\s*=|<img\s+src\s*=\s*['\"]?javascript)",
     "xss"),
    (r"(?:\.\./|\.\.\\|%2e%2e|%252e%252e)", "path_traversal"),
    (r"(?:/etc/passwd|/etc/shadow|/proc/self|/dev/null|cmd\.exe|powershell)",
     "lfi_rfi"),
    (r"(?:;|\||`|\$\(|&&)\s*(?:ls|cat|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)",
     "command_injection"),
]

COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), name)
    for pattern, name in ATTACK_PATTERNS
]


class HTTPHoneypot:
    """
    Sahte HTTP web sunucusu.
    Dizin tarama, SQL injection, XSS ve yetkisiz erişim
    denemelerini kaydeder.
    """

    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_callback):
        http_cfg = config.get("services", {}).get("http", {})
        self.host = http_cfg.get("bind_host", "0.0.0.0")
        self.port = http_cfg.get("bind_port", 8080)
        self.server_banner = http_cfg.get("server_banner",
                                          "Apache/2.4.54 (Ubuntu)")
        self.fake_login_path = http_cfg.get("fake_login_path", "/admin/login")
        self.fake_api_paths = http_cfg.get("fake_api_paths", [])

        self.hp_logger = hp_logger
        self.alert_callback = alert_callback

        self._server_socket = None
        self._running = False

    def start(self):
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_socket.settimeout(1.0)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(200)

        self.hp_logger.logger.info(
            "HTTP Honeypot dinlemede: %s:%d", self.host, self.port
        )

        thread = threading.Thread(
            target=self._accept_loop, name="http-honeypot", daemon=True
        )
        thread.start()

    def stop(self):
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(
                target=self._handle_request,
                args=(client_sock, addr[0], addr[1]),
                name=f"http-client-{addr[0]}",
                daemon=True,
            )
            t.start()

    # ------------------------------------------------------------------ #
    #  HTTP İstek İşleme
    # ------------------------------------------------------------------ #

    def _handle_request(self, sock: socket.socket, src_ip: str, src_port: int):
        session_id = uuid.uuid4().hex[:12]

        try:
            sock.settimeout(30)
            raw = sock.recv(8192)
            if not raw:
                return

            request_text = raw.decode("utf-8", errors="replace")
            lines = request_text.split("\r\n")
            if not lines:
                return

            # İstek satırını ayrıştır
            request_line = lines[0]
            parts = request_line.split(" ")
            if len(parts) < 2:
                return

            method = parts[0]
            raw_path = parts[1]
            path = unquote(raw_path)

            # Header'ları ayrıştır
            headers = {}
            body = ""
            header_end = False
            for line in lines[1:]:
                if not header_end:
                    if line == "":
                        header_end = True
                        continue
                    if ":" in line:
                        key, val = line.split(":", 1)
                        headers[key.strip().lower()] = val.strip()
                else:
                    body += line

            # Bağlantıyı logla
            self.hp_logger.log_event(
                event_type="http_request",
                service="http",
                src_ip=src_ip,
                src_port=src_port,
                details={
                    "method": method,
                    "path": path,
                    "user_agent": headers.get("user-agent", ""),
                    "host": headers.get("host", ""),
                    "session_id": session_id,
                },
            )

            # Saldırı deseni kontrolü
            full_request = path + " " + body
            for pattern, attack_name in COMPILED_PATTERNS:
                if pattern.search(full_request):
                    self.alert_callback(
                        alert_type=attack_name,
                        severity="critical" if attack_name in (
                            "sql_injection", "command_injection"
                        ) else "high",
                        src_ip=src_ip,
                        description=(
                            f"HTTP {attack_name} saldırısı tespit edildi: "
                            f"{method} {path}"
                        ),
                        evidence={
                            "method": method,
                            "path": path,
                            "body": body[:500],
                            "user_agent": headers.get("user-agent", ""),
                            "pattern": attack_name,
                        },
                    )

            # Yanıt üret
            response = self._generate_response(
                method, path, body, headers, src_ip, src_port, session_id
            )
            sock.sendall(response)

        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _generate_response(self, method: str, path: str, body: str,
                           headers: dict, src_ip: str, src_port: int,
                           session_id: str) -> bytes:
        """İstek yoluna göre sahte HTTP yanıtı üret."""

        # --- Login sayfası ---
        if path == self.fake_login_path or path == "/admin/login":
            if method == "POST":
                return self._handle_login_post(
                    body, src_ip, src_port, session_id
                )
            return self._http_response(200, LOGIN_PAGE_HTML,
                                       "text/html; charset=utf-8")

        # --- Sahte API endpoint'leri ---
        if path in FAKE_API_RESPONSE:
            self.hp_logger.log_event(
                event_type="api_access",
                service="http",
                src_ip=src_ip,
                src_port=src_port,
                details={"path": path, "session_id": session_id},
            )
            return self._http_response(
                200,
                json.dumps(FAKE_API_RESPONSE[path], indent=2),
                "application/json",
            )

        # --- .env dosyası ---
        if path == "/.env":
            self.alert_callback(
                alert_type="sensitive_file_access",
                severity="high",
                src_ip=src_ip,
                description=f"Hassas dosya erişim denemesi: {path}",
                evidence={"path": path},
            )
            return self._http_response(200, FAKE_ENV_FILE, "text/plain")

        # --- WordPress admin ---
        if "/wp-admin" in path or "/wp-login" in path:
            self.hp_logger.log_event(
                event_type="cms_scan",
                service="http",
                src_ip=src_ip,
                src_port=src_port,
                details={"path": path, "cms": "wordpress"},
            )
            return self._http_response(
                200, LOGIN_PAGE_HTML, "text/html; charset=utf-8"
            )

        # --- phpMyAdmin ---
        if "/phpmyadmin" in path.lower():
            self.hp_logger.log_event(
                event_type="admin_panel_scan",
                service="http",
                src_ip=src_ip,
                src_port=src_port,
                details={"path": path, "tool": "phpmyadmin"},
            )
            return self._http_response(
                200, LOGIN_PAGE_HTML, "text/html; charset=utf-8"
            )

        # --- Yedek dosya istekleri ---
        if any(ext in path.lower() for ext in
               [".bak", ".zip", ".sql", ".tar", ".gz", ".old", ".conf"]):
            self.alert_callback(
                alert_type="backup_file_access",
                severity="medium",
                src_ip=src_ip,
                description=f"Yedek/konfigürasyon dosyası erişim denemesi: {path}",
                evidence={"path": path},
            )
            return self._http_response(
                200,
                "[Sahte dosya içeriği - Honeypot tarafından sunuldu]",
                "application/octet-stream",
            )

        # --- robots.txt (tarayıcı tuzağı) ---
        if path == "/robots.txt":
            robots = (
                "User-agent: *\n"
                "Disallow: /admin/\n"
                "Disallow: /api/v1/\n"
                "Disallow: /backup/\n"
                "Disallow: /secret/\n"
            )
            return self._http_response(200, robots, "text/plain")

        # --- Root path ---
        if path == "/" or path == "/index.html":
            index_html = """<!DOCTYPE html>
<html><head><title>Corp Server</title></head>
<body><h1>Welcome to Corporate Server</h1>
<p>This server is for authorized personnel only.</p>
<footer>Apache/2.4.54 (Ubuntu)</footer>
</body></html>"""
            return self._http_response(200, index_html,
                                       "text/html; charset=utf-8")

        # --- 404 ---
        return self._http_response(404, NOT_FOUND_HTML,
                                   "text/html; charset=utf-8")

    def _handle_login_post(self, body: str, src_ip: str, src_port: int,
                           session_id: str) -> bytes:
        """Login form POST işlemi."""
        params = {}
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[unquote(k)] = unquote(v)

        username = params.get("username", "")
        password = params.get("password", "")

        self.hp_logger.log_event(
            event_type="login_attempt",
            service="http",
            src_ip=src_ip,
            src_port=src_port,
            details={
                "username": username,
                "password": password,
                "session_id": session_id,
            },
        )

        self.alert_callback(
            alert_type="web_login_attempt",
            severity="medium",
            src_ip=src_ip,
            description=(
                f"HTTP login denemesi: kullanıcı={username}"
            ),
            evidence={
                "username": username,
                "password": password,
                "path": "/admin/login",
            },
        )

        return self._http_response(
            401, LOGIN_FAILED_HTML, "text/html; charset=utf-8"
        )

    def _http_response(self, status_code: int, body: str,
                       content_type: str) -> bytes:
        """HTTP yanıt paketi oluştur."""
        status_messages = {
            200: "OK",
            301: "Moved Permanently",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
        }
        status_msg = status_messages.get(status_code, "Unknown")
        body_bytes = body.encode("utf-8")

        headers = (
            f"HTTP/1.1 {status_code} {status_msg}\r\n"
            f"Server: {self.server_banner}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"X-Powered-By: PHP/8.1.2\r\n"
            f"\r\n"
        )
        return headers.encode("utf-8") + body_bytes
