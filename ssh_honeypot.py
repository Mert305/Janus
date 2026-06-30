"""
Honeypot Erken Uyarı Sistemi - SSH Honeypot (Docker Proxy)
==========================================================
Saldırgan paramiko üzerinden bağlanır, banner/auth/credential bu modülde
toplanır; başarılı login sonrası saldırgan SandboxManager'ın spawn ettiği
gerçek bir Docker konteynerine köprülenir. Her keystroke / her çıktı
byte'ı host tarafından kayda geçer.
"""

import socket
import threading
import time
import uuid

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

    def __init__(self, src_ip: str, src_port: int, logger: HoneypotLogger,
                 fake_creds: dict, max_attempts: int, alert_callback,
                 threat_intel=None, correlation=None):
        super().__init__()
        self.src_ip = src_ip
        self.src_port = src_port
        self.hp_logger = logger
        self.fake_creds = fake_creds
        self.max_attempts = max_attempts
        self.alert_callback = alert_callback
        self.threat_intel = threat_intel
        self.correlation = correlation
        self.auth_attempts = 0
        self.event = threading.Event()
        self.authed_username = "admin"
        # PTY parametreleri (sandbox'a aktarılacak)
        self.term = "xterm"
        self.width = 80
        self.height = 24
        # Pencere boyutu değişimi için proxy callback'i
        self.window_change_handler = None

    def check_auth_password(self, username: str, password: str) -> int:
        self.auth_attempts += 1

        self.hp_logger.log_event(
            event_type="auth_attempt",
            service="ssh",
            src_ip=self.src_ip,
            src_port=self.src_port,
            details={
                "username": username,
                "password": password,
                "attempt": self.auth_attempts,
                "method": "password",
            },
        )

        if self.auth_attempts >= self.max_attempts:
            self.alert_callback(
                alert_type="brute_force",
                severity="high",
                src_ip=self.src_ip,
                description=(
                    f"SSH kaba kuvvet saldırısı: "
                    f"{self.auth_attempts} başarısız deneme"
                ),
                evidence={
                    "last_username": username,
                    "last_password": password,
                    "total_attempts": self.auth_attempts,
                },
            )

        if (username in self.fake_creds
                and self.fake_creds[username] == password):
            import time as _time
            from http_honeypot import env_accessed_ips
            via_env = (self.src_ip in env_accessed_ips and
                       _time.time() - env_accessed_ips.get(self.src_ip, 0) < 3600)

            intel = self.threat_intel.enrich(self.src_ip) if self.threat_intel else {}

            self.hp_logger.log_event(
                event_type="auth_success",
                service="ssh",
                src_ip=self.src_ip,
                src_port=self.src_port,
                details={"username": username, "method": "password",
                         "via_env_leak": via_env,
                         "threat_intel": intel},
            )

            # Correlation: başarılı auth → Credential Access tamamlandı
            if self.correlation:
                self.correlation.on_auth_attempt(
                    self.src_ip, "ssh", username, success=True
                )
                if via_env:
                    self.correlation.on_credential_reuse(self.src_ip, username)

            if via_env:
                self.alert_callback(
                    alert_type="credential_reuse_from_web",
                    severity="critical",
                    src_ip=self.src_ip,
                    description=f"Saldirgan .env'den caldigi credential ile SSH'a girdi! ({username})",
                    evidence={"username": username, "service": "ssh",
                              "env_accessed_ago_sec": round(_time.time() - env_accessed_ips[self.src_ip]),
                              "threat_intel": intel},
                )
            self.authed_username = username
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
        self.term = term.decode() if isinstance(term, bytes) else str(term)
        self.width = int(width) or 80
        self.height = int(height) or 24
        return True

    def check_channel_window_change_request(self, channel, width, height,
                                            pixelwidth, pixelheight) -> bool:
        self.width = int(width) or self.width
        self.height = int(height) or self.height
        if self.window_change_handler:
            try:
                self.window_change_handler(self.width, self.height)
            except Exception:
                pass
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        # exec mode: tek seferlik komut. Sandbox'ta `bash -c` ile çalıştırılır.
        self.exec_command = command.decode() if isinstance(command, bytes) else str(command)
        self.event.set()
        return True

    def get_allowed_auths(self, username: str) -> str:
        return "password"


# ------------------------------------------------------------------ #
#  Docker konteynerine paramiko channel köprüsü
# ------------------------------------------------------------------ #

def proxy_channel_to_sandbox(channel, src_ip, src_port, session_id,
                             hp_logger, alert_callback, sandbox_manager,
                             server_interface, priv_keywords,
                             correlation=None):
    """paramiko channel <-> docker container attach socket.

    İki yön thread olarak pump edilir. channel->sandbox tarafında her
    keystroke biriktirilip Enter'da bir mantıksal komut satırı çıkarılır,
    privilege_escalation_keywords ile eşleşirse alert atılır.
    """
    try:
        sandbox = sandbox_manager.create(
            src_ip=src_ip,
            src_port=src_port,
            term=server_interface.term,
            width=server_interface.width,
            height=server_interface.height,
        )
    except Exception as exc:
        hp_logger.logger.error("sandbox spawn başarısız: %s", exc)
        try:
            channel.sendall(b"\r\nService temporarily unavailable.\r\n")
        except Exception:
            pass
        return

    server_interface.window_change_handler = (
        lambda w, h: sandbox_manager.resize(sandbox, w, h)
    )

    sock = sandbox.socket
    stop = threading.Event()
    cmd_buf = bytearray()
    keywords_lc = [k.lower() for k in (priv_keywords or [])]

    def _emit_command(raw_bytes: bytes):
        try:
            cmd = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            return
        if not cmd.strip():
            return
        hp_logger.log_command(
            service="ssh", src_ip=src_ip,
            command=cmd, session_id=session_id,
        )
        hp_logger.log_event(
            event_type="command",
            service="ssh",
            src_ip=src_ip,
            src_port=src_port,
            details={
                "command": cmd,
                "session_id": session_id,
                "container_id": sandbox.container_id[:12],
            },
        )
        # Correlation Engine feed
        if correlation:
            try:
                correlation.on_command(src_ip, cmd, session_id)
            except Exception:
                pass

        lower = cmd.lower()
        hit = next((k for k in keywords_lc if k in lower), None)
        if hit:
            alert_callback(
                alert_type="privilege_escalation",
                severity="critical",
                src_ip=src_ip,
                description=f"Tehlikeli komut: '{cmd.strip()}'",
                evidence={
                    "command": cmd,
                    "keyword": hit,
                    "session_id": session_id,
                    "container_id": sandbox.container_id[:12],
                },
            )

    def channel_to_sandbox():
        try:
            channel.settimeout(1.0)
            while not stop.is_set():
                try:
                    data = channel.recv(4096)
                except (socket.timeout, TimeoutError):
                    continue
                except Exception:
                    break
                if not data:
                    break

                # Komut satırı assembly (TTY mode keystrokes)
                for b in data:
                    if b in (0x0a, 0x0d):  # Enter
                        if cmd_buf:
                            _emit_command(bytes(cmd_buf))
                            cmd_buf.clear()
                    elif b in (0x7f, 0x08):  # backspace / DEL
                        if cmd_buf:
                            cmd_buf.pop()
                    elif 0x20 <= b < 0x7f:
                        cmd_buf.append(b)

                # Ham byte'ları sandbox stdin'e ilet
                try:
                    sock.sendall(data)
                except Exception:
                    break
        finally:
            stop.set()

    def sandbox_to_channel():
        try:
            while not stop.is_set():
                try:
                    data = sock.recv(4096)
                except BlockingIOError:
                    time.sleep(0.02)
                    continue
                except (OSError, ConnectionError):
                    break
                except Exception:
                    break
                if not data:
                    break
                try:
                    channel.sendall(data)
                except Exception:
                    break
        finally:
            stop.set()

    t1 = threading.Thread(target=channel_to_sandbox, daemon=True,
                          name=f"ssh-c2s-{session_id}")
    t2 = threading.Thread(target=sandbox_to_channel, daemon=True,
                          name=f"ssh-s2c-{session_id}")
    t1.start()
    t2.start()
    t1.join()
    t2.join(timeout=2.0)

    # exec mode'da kalan tampon da log'a düşsün
    if cmd_buf:
        _emit_command(bytes(cmd_buf))
        cmd_buf.clear()

    sandbox_manager.destroy(sandbox.session_id)
    try:
        channel.close()
    except Exception:
        pass


# ------------------------------------------------------------------ #
#  SSH Honeypot Sunucusu
# ------------------------------------------------------------------ #

class SSHHoneypot:
    """Sahte SSH ön kapısı. Auth+banner burada, shell sandbox'ta."""

    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_callback, sandbox_manager,
                 alert_engine=None, threat_intel=None, correlation=None):
        if paramiko is None:
            raise ImportError("paramiko gerekli: pip install paramiko")

        ssh_cfg = config.get("services", {}).get("ssh", {})
        self.host = ssh_cfg.get("bind_host", "0.0.0.0")
        self.port = ssh_cfg.get("bind_port", 2222)
        self.banner = ssh_cfg.get("server_banner",
                                  "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        self.fake_creds = ssh_cfg.get("fake_credentials", {"admin": "admin"})
        self.max_attempts = ssh_cfg.get("max_auth_attempts", 5)
        self.session_timeout = ssh_cfg.get("session_timeout", 300)

        self.priv_keywords = (
            config.get("alerting", {})
                  .get("thresholds", {})
                  .get("privilege_escalation_keywords", [])
        )

        self.hp_logger = hp_logger
        self.alert_callback = alert_callback
        self.alert_engine = alert_engine
        self.threat_intel = threat_intel
        self.correlation = correlation
        self.sandbox_manager = sandbox_manager

        self.host_key = paramiko.RSAKey.generate(2048)

        self._server_socket = None
        self._running = False

    def start(self):
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(100)

        self.hp_logger.logger.info(
            "SSH Honeypot dinlemede: %s:%d (sandbox proxy)",
            self.host, self.port,
        )

        threading.Thread(
            target=self._accept_loop, name="ssh-honeypot", daemon=True
        ).start()

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
                service="ssh",
                src_ip=src_ip,
                src_port=src_port,
                details={"state": "new"},
            )
            if self.alert_engine is not None:
                try:
                    self.alert_engine.track_connection(src_ip, "ssh", self.port)
                except Exception as e:
                    self.hp_logger.logger.debug("alert_engine track: %s", e)

            # Threat Intel: yeni bağlantı zenginleştirme (arka plan)
            if self.threat_intel:
                try:
                    summary = self.threat_intel.summary_line(src_ip)
                    if summary != "no intel":
                        self.hp_logger.logger.info(
                            "ThreatIntel [SSH] %s: %s", src_ip, summary
                        )
                except Exception:
                    pass

            # Correlation: SSH bağlantısı = Credential Access başlangıcı
            if self.correlation:
                try:
                    self.correlation.record_event(
                        src_ip, "Credential Access", "ssh",
                        {"event": "connection"}
                    )
                except Exception:
                    pass

            threading.Thread(
                target=self._handle_client,
                args=(client_sock, src_ip, src_port),
                name=f"ssh-client-{src_ip}",
                daemon=True,
            ).start()

    def _handle_client(self, client_sock: socket.socket,
                       src_ip: str, src_port: int):
        session_id = uuid.uuid4().hex[:12]
        transport = None
        try:
            client_sock.settimeout(self.session_timeout)

            transport = paramiko.Transport(client_sock)
            transport.local_version = self.banner
            transport.add_server_key(self.host_key)

            server_interface = FakeSSHServerInterface(
                src_ip=src_ip,
                src_port=src_port,
                logger=self.hp_logger,
                fake_creds=self.fake_creds,
                max_attempts=self.max_attempts,
                alert_callback=self.alert_callback,
                threat_intel=self.threat_intel,
                correlation=self.correlation,
            )

            transport.start_server(server=server_interface)

            channel = transport.accept(timeout=30)
            if channel is None:
                return

            # Shell veya exec isteğini bekle
            server_interface.event.wait(timeout=10)

            proxy_channel_to_sandbox(
                channel=channel,
                src_ip=src_ip,
                src_port=src_port,
                session_id=session_id,
                hp_logger=self.hp_logger,
                alert_callback=self.alert_callback,
                sandbox_manager=self.sandbox_manager,
                server_interface=server_interface,
                priv_keywords=self.priv_keywords,
                correlation=self.correlation,
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
        except Exception as exc:
            self.hp_logger.logger.debug("ssh handle_client: %s", exc)
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
