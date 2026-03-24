"""
Honeypot Erken Uyarı Sistemi - FTP Honeypot Modülü
===================================================
Sahte bir FTP servisi sunarak yetkisiz erişim denemelerini,
dosya yükleme/indirme girişimlerini ve zararlı yazılım
sızdırma denemelerini kaydeder.

Socket tabanlı, sıfırdan kodlanmış FTP protokol simülasyonu.
"""

import socket
import threading
import uuid
import os
import hashlib
from datetime import datetime, timezone

from logger import HoneypotLogger


# ------------------------------------------------------------------ #
#  Sahte FTP Dosya Sistemi
# ------------------------------------------------------------------ #

FAKE_FTP_FS = {
    "/": {
        "type": "dir",
        "children": ["home", "var", "etc", "backup"],
    },
    "/home": {
        "type": "dir",
        "children": ["admin", "ftpuser"],
    },
    "/home/admin": {
        "type": "dir",
        "children": ["passwords.txt", ".ssh"],
    },
    "/home/admin/passwords.txt": {
        "type": "file",
        "size": 245,
        "content": (
            "# Sunucu Şifreleri (Gizli)\n"
            "db_root: MySQL_R00t_2024!\n"
            "admin_panel: Adm1n@Corp\n"
            "backup_ftp: Bkp_Ftp#99\n"
        ),
    },
    "/var": {
        "type": "dir",
        "children": ["backups", "www", "log"],
    },
    "/var/backups": {
        "type": "dir",
        "children": ["db_dump.sql", "site_backup.tar.gz"],
    },
    "/var/backups/db_dump.sql": {
        "type": "file",
        "size": 5242880,
        "content": "-- MySQL dump placeholder\n",
    },
    "/etc": {
        "type": "dir",
        "children": ["passwd", "shadow.bak"],
    },
    "/etc/passwd": {
        "type": "file",
        "size": 1024,
        "content": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n",
    },
    "/etc/shadow.bak": {
        "type": "file",
        "size": 512,
        "content": "root:$6$rounds=656000$salt$hash:19000:0:99999:7:::\n",
    },
    "/backup": {
        "type": "dir",
        "children": ["config_2024.zip"],
    },
    "/backup/config_2024.zip": {
        "type": "file",
        "size": 10485760,
        "content": "[binary data placeholder]",
    },
}


class FTPHoneypot:
    """
    Sahte FTP servisi.
    Yetkisiz erişim, dosya indirme/yükleme ve zararlı yazılım
    sızdırma girişimlerini kaydeder.
    """

    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_callback):
        ftp_cfg = config.get("services", {}).get("ftp", {})
        self.host = ftp_cfg.get("bind_host", "0.0.0.0")
        self.port = ftp_cfg.get("bind_port", 2121)
        self.banner = ftp_cfg.get("server_banner",
                                  "220 corp-ftp-01 FTP server ready.")
        self.fake_creds = ftp_cfg.get("fake_credentials",
                                      {"anonymous": "", "admin": "ftp@admin"})
        self.max_attempts = ftp_cfg.get("max_auth_attempts", 5)

        self.hp_logger = hp_logger
        self.alert_callback = alert_callback

        # Yüklenen dosyaları sakla (zararlı yazılım analizi için)
        self.upload_dir = os.path.join(
            config.get("general", {}).get("log_directory", "logs"),
            "ftp_uploads",
        )
        os.makedirs(self.upload_dir, exist_ok=True)

        self._server_socket = None
        self._running = False

    def start(self):
        """FTP honeypot'u başlat."""
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_socket.settimeout(1.0)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(100)

        self.hp_logger.logger.info(
            "FTP Honeypot dinlemede: %s:%d", self.host, self.port
        )

        thread = threading.Thread(
            target=self._accept_loop, name="ftp-honeypot", daemon=True
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

            src_ip, src_port = addr
            self.hp_logger.log_event(
                event_type="connection",
                service="ftp",
                src_ip=src_ip,
                src_port=src_port,
                details={"state": "new"},
            )

            t = threading.Thread(
                target=self._handle_client,
                args=(client_sock, src_ip, src_port),
                name=f"ftp-client-{src_ip}",
                daemon=True,
            )
            t.start()

    # ------------------------------------------------------------------ #
    #  FTP İstemci İşleme (Protokol Simülasyonu)
    # ------------------------------------------------------------------ #

    def _handle_client(self, sock: socket.socket, src_ip: str, src_port: int):
        session_id = uuid.uuid4().hex[:12]
        authenticated = False
        username = ""
        cwd = "/"
        auth_attempts = 0
        data_sock = None
        rename_from = None

        try:
            sock.settimeout(300)
            # Banner gönder
            self._send(sock, self.banner)

            while self._running:
                try:
                    raw = sock.recv(4096)
                except socket.timeout:
                    break
                except Exception:
                    break

                if not raw:
                    break

                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1].strip() if len(parts) > 1 else ""

                # Komutu logla
                self.hp_logger.log_command(
                    service="ftp",
                    src_ip=src_ip,
                    command=line,
                    session_id=session_id,
                )

                # ---- Kimlik Doğrulama ----
                if cmd == "USER":
                    username = arg
                    self.hp_logger.log_event(
                        event_type="auth_attempt",
                        service="ftp",
                        src_ip=src_ip,
                        src_port=src_port,
                        details={"username": username, "step": "USER"},
                    )
                    self._send(sock, "331 Password required for " + username)
                    continue

                if cmd == "PASS":
                    password = arg
                    auth_attempts += 1

                    self.hp_logger.log_event(
                        event_type="auth_attempt",
                        service="ftp",
                        src_ip=src_ip,
                        src_port=src_port,
                        details={
                            "username": username,
                            "password": password,
                            "attempt": auth_attempts,
                            "step": "PASS",
                        },
                    )

                    if auth_attempts >= self.max_attempts:
                        self.alert_callback(
                            alert_type="brute_force",
                            severity="high",
                            src_ip=src_ip,
                            description=(
                                f"FTP kaba kuvvet saldırısı: "
                                f"{auth_attempts} başarısız deneme"
                            ),
                            evidence={
                                "username": username,
                                "total_attempts": auth_attempts,
                            },
                        )

                    # Sahte kimlik kontrolü
                    if (username in self.fake_creds
                            and self.fake_creds[username] == password):
                        authenticated = True
                        self.hp_logger.log_event(
                            event_type="auth_success",
                            service="ftp",
                            src_ip=src_ip,
                            src_port=src_port,
                            details={"username": username},
                        )
                        self._send(sock, "230 Login successful.")
                    elif username == "anonymous":
                        authenticated = True
                        self._send(sock, "230 Anonymous login ok.")
                    else:
                        self._send(sock, "530 Login incorrect.")
                    continue

                # Kimlik doğrulanmamış komutlar
                if not authenticated:
                    self._send(sock, "530 Please login with USER and PASS.")
                    continue

                # ---- FTP Komutları ----
                if cmd == "SYST":
                    self._send(sock, "215 UNIX Type: L8")

                elif cmd == "FEAT":
                    self._send(sock, "211-Features:\r\n PASV\r\n UTF8\r\n211 End")

                elif cmd == "PWD" or cmd == "XPWD":
                    self._send(sock, f'257 "{cwd}" is the current directory')

                elif cmd == "CWD" or cmd == "XCWD":
                    target = self._resolve_path(cwd, arg)
                    if target in FAKE_FTP_FS and FAKE_FTP_FS[target]["type"] == "dir":
                        cwd = target
                        self._send(sock, f"250 Directory changed to {cwd}")
                    else:
                        self._send(sock, "550 Failed to change directory.")

                elif cmd == "CDUP":
                    cwd = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
                    self._send(sock, f"250 Directory changed to {cwd}")

                elif cmd == "TYPE":
                    self._send(sock, f"200 Type set to {arg}")

                elif cmd == "PASV":
                    # Pasif mod - veri bağlantısı aç
                    data_sock = self._create_data_socket(sock, src_ip)

                elif cmd == "LIST" or cmd == "NLST":
                    listing = self._generate_listing(cwd)
                    self._send(sock, "150 Opening data connection.")
                    if data_sock:
                        try:
                            conn, _ = data_sock.accept()
                            conn.sendall(listing.encode("utf-8"))
                            conn.close()
                        except Exception:
                            pass
                        data_sock.close()
                        data_sock = None
                    self._send(sock, "226 Transfer complete.")

                elif cmd == "RETR":
                    filepath = self._resolve_path(cwd, arg)
                    self.hp_logger.log_event(
                        event_type="file_download",
                        service="ftp",
                        src_ip=src_ip,
                        src_port=src_port,
                        details={
                            "filepath": filepath,
                            "session_id": session_id,
                        },
                    )

                    if (filepath in FAKE_FTP_FS
                            and FAKE_FTP_FS[filepath]["type"] == "file"):
                        content = FAKE_FTP_FS[filepath].get("content", "")
                        self._send(sock, "150 Opening BINARY mode data connection.")
                        if data_sock:
                            try:
                                conn, _ = data_sock.accept()
                                conn.sendall(content.encode("utf-8"))
                                conn.close()
                            except Exception:
                                pass
                            data_sock.close()
                            data_sock = None
                        self._send(sock, "226 Transfer complete.")
                    else:
                        self._send(sock, "550 File not found.")

                elif cmd == "STOR":
                    filepath = self._resolve_path(cwd, arg)
                    self._send(sock, "150 Ok to send data.")

                    uploaded_data = b""
                    if data_sock:
                        try:
                            conn, _ = data_sock.accept()
                            while True:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                uploaded_data += chunk
                            conn.close()
                        except Exception:
                            pass
                        data_sock.close()
                        data_sock = None

                    # Yüklenen dosyayı kaydet ve alarmla
                    file_hash = hashlib.sha256(uploaded_data).hexdigest()
                    safe_name = filepath.replace("/", "_").replace("\\", "_")
                    save_path = os.path.join(
                        self.upload_dir,
                        f"{session_id}_{safe_name}",
                    )
                    with open(save_path, "wb") as f:
                        f.write(uploaded_data)

                    self.hp_logger.log_event(
                        event_type="file_upload",
                        service="ftp",
                        src_ip=src_ip,
                        src_port=src_port,
                        details={
                            "filepath": filepath,
                            "size": len(uploaded_data),
                            "sha256": file_hash,
                            "saved_as": save_path,
                            "session_id": session_id,
                        },
                    )

                    # Zararlı yazılım yükleme alarmı
                    self.alert_callback(
                        alert_type="malware_upload",
                        severity="critical",
                        src_ip=src_ip,
                        description=(
                            f"FTP dosya yükleme tespit edildi: {filepath} "
                            f"({len(uploaded_data)} byte)"
                        ),
                        evidence={
                            "filepath": filepath,
                            "size": len(uploaded_data),
                            "sha256": file_hash,
                            "session_id": session_id,
                        },
                    )

                    self._send(sock, "226 Transfer complete.")

                elif cmd == "SIZE":
                    filepath = self._resolve_path(cwd, arg)
                    if (filepath in FAKE_FTP_FS
                            and FAKE_FTP_FS[filepath]["type"] == "file"):
                        size = FAKE_FTP_FS[filepath].get("size", 0)
                        self._send(sock, f"213 {size}")
                    else:
                        self._send(sock, "550 File not found.")

                elif cmd == "DELE":
                    filepath = self._resolve_path(cwd, arg)
                    self.hp_logger.log_event(
                        event_type="file_delete",
                        service="ftp",
                        src_ip=src_ip,
                        src_port=src_port,
                        details={"filepath": filepath, "session_id": session_id},
                    )
                    self._send(sock, "250 File deleted.")

                elif cmd == "MKD" or cmd == "XMKD":
                    self._send(sock, f'257 "{arg}" created')

                elif cmd == "RMD" or cmd == "XRMD":
                    self._send(sock, "250 Directory removed.")

                elif cmd == "RNFR":
                    rename_from = self._resolve_path(cwd, arg)
                    self._send(sock, "350 Ready for RNTO.")

                elif cmd == "RNTO":
                    self._send(sock, "250 Rename successful.")
                    rename_from = None

                elif cmd == "QUIT":
                    self._send(sock, "221 Goodbye.")
                    break

                elif cmd == "NOOP":
                    self._send(sock, "200 NOOP ok.")

                elif cmd == "HELP":
                    self._send(
                        sock,
                        "214-Commands recognized:\r\n"
                        " USER PASS SYST FEAT PWD CWD LIST RETR STOR QUIT\r\n"
                        "214 Help OK.",
                    )

                else:
                    self._send(sock, f"502 Command '{cmd}' not implemented.")

        except Exception:
            pass
        finally:
            if data_sock:
                try:
                    data_sock.close()
                except Exception:
                    pass
            try:
                sock.close()
            except Exception:
                pass

            self.hp_logger.log_event(
                event_type="disconnection",
                service="ftp",
                src_ip=src_ip,
                src_port=src_port,
                details={"session_id": session_id, "username": username},
            )

    # ------------------------------------------------------------------ #
    #  Yardımcı Metotlar
    # ------------------------------------------------------------------ #

    @staticmethod
    def _send(sock: socket.socket, message: str):
        """FTP yanıtı gönder (\r\n sonlandırmalı)."""
        try:
            sock.sendall((message + "\r\n").encode("utf-8"))
        except Exception:
            pass

    @staticmethod
    def _resolve_path(cwd: str, path: str) -> str:
        """Göreceli yolu mutlak yola çevir."""
        if not path:
            return cwd
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        # Göreceli
        if cwd == "/":
            return "/" + path.rstrip("/")
        return cwd.rstrip("/") + "/" + path.rstrip("/")

    def _create_data_socket(self, control_sock: socket.socket,
                            src_ip: str) -> socket.socket:
        """Pasif mod için veri soketi oluştur."""
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_sock.bind(("0.0.0.0", 0))
        data_sock.listen(1)
        data_sock.settimeout(30)

        _, data_port = data_sock.getsockname()

        # PASV yanıtında IP ve port bilgisi
        ip_parts = self.host if self.host != "0.0.0.0" else "127.0.0.1"
        ip_str = ip_parts.replace(".", ",")
        p1 = data_port // 256
        p2 = data_port % 256

        self._send(
            control_sock,
            f"227 Entering Passive Mode ({ip_str},{p1},{p2})",
        )
        return data_sock

    @staticmethod
    def _generate_listing(cwd: str) -> str:
        """ls -la benzeri dosya listesi üret."""
        lines = []
        if cwd in FAKE_FTP_FS and FAKE_FTP_FS[cwd]["type"] == "dir":
            for child in FAKE_FTP_FS[cwd].get("children", []):
                child_path = cwd.rstrip("/") + "/" + child
                if child_path in FAKE_FTP_FS:
                    entry = FAKE_FTP_FS[child_path]
                    if entry["type"] == "dir":
                        lines.append(
                            f"drwxr-xr-x   2 root root     4096 "
                            f"Jan 15 10:30 {child}"
                        )
                    else:
                        size = entry.get("size", 0)
                        lines.append(
                            f"-rw-r--r--   1 admin admin {size:>8} "
                            f"Jan 15 10:30 {child}"
                        )
                else:
                    lines.append(
                        f"-rw-r--r--   1 admin admin        0 "
                        f"Jan 15 10:30 {child}"
                    )

        return "\r\n".join(lines) + "\r\n"
