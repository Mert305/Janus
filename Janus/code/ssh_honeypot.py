"""
Honeypot Erken Uyarı Sistemi - SSH Honeypot Modülü
===================================================
Sahte bir SSH servisi sunarak kaba kuvvet saldırılarını,
yetkisiz erişim denemelerini ve saldırgan komutlarını kaydeder.

Paramiko kütüphanesi ile gerçekçi bir SSH sunucu simüle eder.
"""

import socket
import threading
import uuid
import os
import time

try:
    import paramiko
except ImportError:
    paramiko = None

from logger import HoneypotLogger


# ------------------------------------------------------------------ #
#  Sahte SSH Sunucu Arayüzü (Paramiko ServerInterface)
# ------------------------------------------------------------------ #

class FakeSSHServerInterface(paramiko.ServerInterface):
    """Saldırganı karşılayan sahte SSH oturum yöneticisi."""

    def __init__(self, src_ip: str, logger: HoneypotLogger,
                 fake_creds: dict, max_attempts: int, alert_callback):
        super().__init__()
        self.src_ip = src_ip
        self.hp_logger = logger
        self.fake_creds = fake_creds
        self.max_attempts = max_attempts
        self.alert_callback = alert_callback
        self.auth_attempts = 0
        self.event = threading.Event()

    # -- Kimlik doğrulama (parola) --
    def check_auth_password(self, username: str, password: str) -> int:
        self.auth_attempts += 1

        # Her denemeyi logla
        self.hp_logger.log_event(
            event_type="auth_attempt",
            service="ssh",
            src_ip=self.src_ip,
            src_port=0,
            details={
                "username": username,
                "password": password,
                "attempt": self.auth_attempts,
                "method": "password",
            },
        )

        # Eşik kontrolü → alarm
        if self.auth_attempts >= self.max_attempts:
            self.alert_callback(
                alert_type="brute_force",
                severity="high",
                src_ip=self.src_ip,
                description=(
                    f"SSH kaba kuvvet saldırısı tespit edildi: "
                    f"{self.auth_attempts} başarısız deneme"
                ),
                evidence={
                    "last_username": username,
                    "last_password": password,
                    "total_attempts": self.auth_attempts,
                },
            )

        # Sahte credential eşleşmesi → saldırganı içeri al (gözlem)
        if (username in self.fake_creds
                and self.fake_creds[username] == password):
            self.hp_logger.log_event(
                event_type="auth_success",
                service="ssh",
                src_ip=self.src_ip,
                src_port=0,
                details={"username": username, "method": "password"},
            )
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        self.event.set()
        return True

    def get_allowed_auths(self, username: str) -> str:
        return "password"


# ------------------------------------------------------------------ #
#  Sahte Kabuk (Shell) - Saldırgan komutlarını yakalar
# ------------------------------------------------------------------ #

FAKE_FILESYSTEM = {
    "/": ["bin", "etc", "home", "var", "tmp", "usr"],
    "/home": ["admin", "user"],
    "/home/admin": [".bash_history", ".ssh", "notes.txt"],
    "/etc": ["passwd", "shadow", "hosts", "ssh"],
    "/var": ["log", "www"],
    "/tmp": [],
}

FAKE_FILE_CONTENTS = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
        "user:x:1001:1001:User:/home/user:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    ),
    "/etc/shadow": "Permission denied\n",
    "/etc/hosts": (
        "127.0.0.1  localhost\n"
        "192.168.56.10  corp-server-01\n"
        "192.168.56.20  corp-db-01\n"
    ),
    "/home/admin/notes.txt": (
        "TODO: Sunucu yedeklemesini ayarla\n"
        "DB şifresi: Passw0rd_2024!  (değiştirilecek)\n"
    ),
}


def handle_fake_shell(channel, src_ip: str, session_id: str,
                      hp_logger: HoneypotLogger, alert_callback):
    """Saldırganla etkileşimli sahte kabuk oturumu."""
    cwd = "/home/admin"
    hostname = "corp-server-01"
    username = "admin"

    priv_escalation_keywords = [
        "sudo", "su ", "su\n", "/etc/shadow", "chmod +s",
        "wget ", "curl ", "nc ", "bash -i", "python -c",
        "/etc/passwd", "id", "whoami",
    ]

    try:
        channel.sendall(f"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n".encode())
        prompt = f"{username}@{hostname}:{cwd}$ "
        channel.sendall(prompt.encode())

        command_buffer = ""

        while True:
            try:
                data = channel.recv(1024)
            except socket.timeout:
                continue
            except Exception:
                break

            if not data:
                break

            for byte in data:
                char = chr(byte)

                # Enter tuşu
                if char in ("\r", "\n"):
                    cmd = command_buffer.strip()
                    command_buffer = ""

                    if not cmd:
                        channel.sendall(f"\r\n{prompt}".encode())
                        continue

                    # Komutu logla
                    hp_logger.log_command(
                        service="ssh",
                        src_ip=src_ip,
                        command=cmd,
                        session_id=session_id,
                    )

                    hp_logger.log_event(
                        event_type="command",
                        service="ssh",
                        src_ip=src_ip,
                        src_port=0,
                        details={
                            "command": cmd,
                            "session_id": session_id,
                            "cwd": cwd,
                        },
                    )

                    # Yetki yükseltme kontrolü
                    for keyword in priv_escalation_keywords:
                        if keyword in cmd.lower():
                            alert_callback(
                                alert_type="privilege_escalation",
                                severity="critical",
                                src_ip=src_ip,
                                description=(
                                    f"Yetki yükseltme girişimi: '{cmd}'"
                                ),
                                evidence={
                                    "command": cmd,
                                    "keyword": keyword,
                                    "session_id": session_id,
                                },
                            )
                            break

                    # Sahte komut yanıtları
                    response = _process_fake_command(cmd, cwd)

                    # cd komutu → dizin değiştir
                    if cmd.startswith("cd "):
                        target = cmd[3:].strip()
                        if target in FAKE_FILESYSTEM or target == "..":
                            if target == "..":
                                cwd = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
                            else:
                                cwd = target
                        prompt = f"{username}@{hostname}:{cwd}$ "

                    if cmd in ("exit", "quit", "logout"):
                        channel.sendall(b"\r\nlogout\r\n")
                        return

                    channel.sendall(f"\r\n{response}{prompt}".encode())

                # Backspace
                elif char == "\x7f" or char == "\x08":
                    if command_buffer:
                        command_buffer = command_buffer[:-1]
                        channel.sendall(b"\x08 \x08")
                else:
                    command_buffer += char
                    channel.sendall(char.encode())

    except Exception:
        pass
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _process_fake_command(cmd: str, cwd: str) -> str:
    """Sahte komut çıktıları üret."""
    parts = cmd.split()
    if not parts:
        return ""

    base_cmd = parts[0]

    if base_cmd == "ls":
        target = parts[1] if len(parts) > 1 else cwd
        if target in FAKE_FILESYSTEM:
            items = FAKE_FILESYSTEM[target]
            return "  ".join(items) + "\r\n" if items else "\r\n"
        return f"ls: cannot access '{target}': No such file or directory\r\n"

    elif base_cmd == "cat":
        if len(parts) < 2:
            return "cat: missing operand\r\n"
        filepath = parts[1]
        if filepath in FAKE_FILE_CONTENTS:
            return FAKE_FILE_CONTENTS[filepath].replace("\n", "\r\n")
        return f"cat: {filepath}: No such file or directory\r\n"

    elif base_cmd == "pwd":
        return cwd + "\r\n"

    elif base_cmd == "id":
        return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\r\n"

    elif base_cmd == "whoami":
        return "admin\r\n"

    elif base_cmd == "uname":
        if "-a" in parts:
            return "Linux corp-server-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"
        return "Linux\r\n"

    elif base_cmd == "hostname":
        return "corp-server-01\r\n"

    elif base_cmd == "ifconfig" or (base_cmd == "ip" and "addr" in cmd):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 192.168.56.10  netmask 255.255.255.0  broadcast 192.168.56.255\r\n"
            "        ether 08:00:27:a1:b2:c3  txqueuelen 1000\r\n\r\n"
        )

    elif base_cmd == "ps":
        return (
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:05 systemd\r\n"
            "  412 ?        00:00:02 sshd\r\n"
            "  680 ?        00:00:01 apache2\r\n"
            " 1024 pts/0    00:00:00 bash\r\n"
        )

    elif base_cmd == "netstat" or (base_cmd == "ss" and len(parts) > 0):
        return (
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\r\n"
        )

    elif base_cmd in ("wget", "curl"):
        return f"Connecting... failed: Network is unreachable\r\n"

    elif base_cmd == "sudo":
        return "[sudo] password for admin: \r\nSorry, try again.\r\n"

    elif base_cmd == "su":
        return "Password: \r\nsu: Authentication failure\r\n"

    elif base_cmd == "help":
        return (
            "GNU bash, version 5.1.16\r\n"
            "Type 'help name' for more information.\r\n"
        )

    elif base_cmd == "history":
        return (
            "    1  ls -la\r\n"
            "    2  cat /etc/passwd\r\n"
            "    3  sudo apt update\r\n"
            "    4  df -h\r\n"
        )

    elif base_cmd == "df":
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\r\n"
            "/dev/sda1        50G   12G   36G  25% /\r\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm\r\n"
        )

    elif base_cmd == "echo":
        return " ".join(parts[1:]) + "\r\n"

    elif base_cmd == "date":
        return time.strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n"

    elif base_cmd == "uptime":
        return " 14:23:01 up 32 days,  5:12,  1 user,  load average: 0.08, 0.03, 0.01\r\n"

    elif base_cmd in ("exit", "quit", "logout"):
        return ""

    else:
        return f"-bash: {base_cmd}: command not found\r\n"


# ------------------------------------------------------------------ #
#  SSH Honeypot Sunucusu
# ------------------------------------------------------------------ #

class SSHHoneypot:
    """
    Sahte SSH servisi.
    Kaba kuvvet saldırılarını ve saldırgan komutlarını kaydeder.
    """

    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_callback):
        if paramiko is None:
            raise ImportError(
                "paramiko kütüphanesi gerekli: pip install paramiko"
            )

        ssh_cfg = config.get("services", {}).get("ssh", {})
        self.host = ssh_cfg.get("bind_host", "0.0.0.0")
        self.port = ssh_cfg.get("bind_port", 2222)
        self.banner = ssh_cfg.get("server_banner",
                                  "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        self.fake_creds = ssh_cfg.get("fake_credentials", {"admin": "admin"})
        self.max_attempts = ssh_cfg.get("max_auth_attempts", 5)
        self.session_timeout = ssh_cfg.get("session_timeout", 300)

        self.hp_logger = hp_logger
        self.alert_callback = alert_callback

        # RSA host anahtarı oluştur
        self.host_key = paramiko.RSAKey.generate(2048)

        self._server_socket = None
        self._running = False

    def start(self):
        """SSH honeypot'u başlat."""
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_socket.settimeout(1.0)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(100)

        self.hp_logger.logger.info(
            "SSH Honeypot dinlemede: %s:%d", self.host, self.port
        )

        thread = threading.Thread(
            target=self._accept_loop, name="ssh-honeypot", daemon=True
        )
        thread.start()

    def stop(self):
        """Sunucuyu durdur."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

    def _accept_loop(self):
        """Bağlantı kabul döngüsü."""
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
                service="ssh",
                src_ip=src_ip,
                src_port=src_port,
                details={"state": "new"},
            )

            # Her bağlantıyı ayrı thread'de işle
            t = threading.Thread(
                target=self._handle_client,
                args=(client_sock, src_ip, src_port),
                name=f"ssh-client-{src_ip}",
                daemon=True,
            )
            t.start()

    def _handle_client(self, client_sock: socket.socket,
                       src_ip: str, src_port: int):
        """Tek bir SSH istemcisini işle."""
        session_id = uuid.uuid4().hex[:12]
        transport = None
        try:
            client_sock.settimeout(self.session_timeout)

            transport = paramiko.Transport(client_sock)
            transport.local_version = self.banner
            transport.add_server_key(self.host_key)

            server_interface = FakeSSHServerInterface(
                src_ip=src_ip,
                logger=self.hp_logger,
                fake_creds=self.fake_creds,
                max_attempts=self.max_attempts,
                alert_callback=self.alert_callback,
            )

            transport.start_server(server=server_interface)

            # Kanal açılmasını bekle
            channel = transport.accept(timeout=30)
            if channel is None:
                return

            # Kabuk isteğini bekle
            server_interface.event.wait(timeout=10)

            # Sahte kabuk oturumu başlat
            handle_fake_shell(
                channel=channel,
                src_ip=src_ip,
                session_id=session_id,
                hp_logger=self.hp_logger,
                alert_callback=self.alert_callback,
            )

        except paramiko.SSHException:
            pass
        except socket.timeout:
            self.hp_logger.log_event(
                event_type="timeout",
                service="ssh",
                src_ip=src_ip,
                src_port=src_port,
                details={"session_id": session_id},
            )
        except Exception:
            pass
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass

            self.hp_logger.log_event(
                event_type="disconnection",
                service="ssh",
                src_ip=src_ip,
                src_port=src_port,
                details={"session_id": session_id},
            )
