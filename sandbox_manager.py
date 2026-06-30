"""
sandbox_manager.py - Yüksek etkileşimli SSH sandbox motoru
==========================================================
Her başarılı SSH login'de Dockerfile.sandbox'tan tek kullanımlık bir
konteyner spawn eder; saldırganın paramiko channel'ı bu konteynerin
attach soketine köprülenir, böylece gerçek bir bash, gerçek `ls`,
`cat`, `wget`... çalışır. Oturum kapanınca konteyner kill+remove edilir.

İzolasyon: --network none, --read-only + tmpfs, cap_drop=ALL,
no-new-privileges, mem/cpu/pids limit, session_ttl_sec watchdog.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

try:
    import docker
    from docker.errors import ImageNotFound
except ImportError:
    docker = None


@dataclass
class SandboxSession:
    session_id: str
    container_id: str
    container: object
    socket: object
    started_at: float = field(default_factory=time.time)
    src_ip: str = ""
    src_port: int = 0
    closed: bool = False


class SandboxManager:
    def __init__(self, config: dict, hp_logger):
        if docker is None:
            raise RuntimeError("docker python SDK kurulu değil — `pip install docker`")
        self.config = config
        self.hp_logger = hp_logger
        self.log = hp_logger.logger
        docker_cfg = config.get("docker") or {}
        self.cfg = docker_cfg.get("sandbox") or {}
        self.image = self.cfg.get("image", "janus-sandbox:latest")
        self.session_ttl = int(self.cfg.get("session_ttl_sec", 600))
        self.max_concurrent = int(self.cfg.get("max_concurrent", 20))
        self.client = self._connect(docker_cfg.get("socket", "auto"))
        self.sessions: Dict[str, SandboxSession] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._watchdog = threading.Thread(
            target=self._watchdog_loop, name="sandbox-watchdog", daemon=True
        )

    # ----- public ----------------------------------------------------------
    def start(self):
        self._ensure_image()
        self._watchdog.start()
        self.log.info("sandbox_manager hazır (image=%s, ttl=%ds, max=%d)",
                      self.image, self.session_ttl, self.max_concurrent)

    def stop(self):
        self._stop.set()
        with self._lock:
            ids = list(self.sessions.keys())
        for sid in ids:
            self.destroy(sid)

    def create(self, src_ip: str, src_port: int, term: str = "xterm",
               width: int = 80, height: int = 24) -> SandboxSession:
        with self._lock:
            if len(self.sessions) >= self.max_concurrent:
                raise RuntimeError("max_concurrent sandbox limiti doldu")

        session_id = uuid.uuid4().hex[:12]
        name = f"janus-sandbox-{session_id}"

        container = self.client.containers.run(
            self.image, **self._run_kwargs(name, term)
        )
        try:
            container.resize(height=height, width=width)
        except Exception as e:
            self.log.debug("container resize başarısız: %s", e)

        sock = container.attach_socket(
            params={"stdin": 1, "stdout": 1, "stderr": 1, "stream": 1}
        )
        raw = getattr(sock, "_sock", sock)
        try:
            raw.setblocking(False)
        except Exception:
            pass

        session = SandboxSession(
            session_id=session_id,
            container_id=container.id,
            container=container,
            socket=raw,
            src_ip=src_ip,
            src_port=src_port,
        )
        with self._lock:
            self.sessions[session_id] = session

        self.hp_logger.log_event(
            event_type="sandbox_spawn",
            service="ssh",
            src_ip=src_ip,
            src_port=src_port,
            details={
                "session_id": session_id,
                "container_id": container.short_id,
                "image": self.image,
            },
        )
        return session

    def destroy(self, session_id: str):
        with self._lock:
            session = self.sessions.pop(session_id, None)
        if not session or session.closed:
            return
        session.closed = True
        duration = time.time() - session.started_at
        try:
            session.container.kill()
        except Exception as e:
            self.log.debug("container kill hata: %s", e)
        try:
            session.container.remove(force=True)
        except Exception as e:
            self.log.debug("container remove hata: %s", e)
        try:
            session.socket.close()
        except Exception:
            pass
        self.hp_logger.log_event(
            event_type="sandbox_destroy",
            service="ssh",
            src_ip=session.src_ip,
            src_port=session.src_port,
            details={
                "session_id": session_id,
                "duration_sec": round(duration, 2),
            },
        )

    def resize(self, session: SandboxSession, width: int, height: int):
        try:
            session.container.resize(height=height, width=width)
        except Exception as e:
            self.log.debug("resize hata: %s", e)

    # ----- internals -------------------------------------------------------
    def _connect(self, socket_uri: str):
        if socket_uri in (None, "", "auto"):
            return docker.from_env()
        return docker.DockerClient(base_url=socket_uri)

    def _ensure_image(self):
        try:
            self.client.images.get(self.image)
            return
        except ImageNotFound:
            pass
        ctx = self.cfg.get("build_context", "docker")
        dockerfile = self.cfg.get("dockerfile", "docker/Dockerfile.sandbox")
        rel = os.path.relpath(dockerfile, ctx) if os.path.isabs(dockerfile) or dockerfile.startswith(ctx) else dockerfile
        self.log.info("image %s yok — %s/%s'den derleniyor", self.image, ctx, rel)
        self.client.images.build(path=ctx, dockerfile=rel, tag=self.image, rm=True)
        self.log.info("image %s hazır", self.image)

    def _run_kwargs(self, name: str, term: str) -> dict:
        kw = dict(
            name=name,
            command="/bin/bash -i",
            detach=True,
            tty=True,
            stdin_open=True,
            network_mode=self.cfg.get("network_mode", "none"),
            read_only=bool(self.cfg.get("read_only", True)),
            cap_drop=list(self.cfg.get("cap_drop", ["ALL"])),
            security_opt=list(self.cfg.get("security_opt", ["no-new-privileges:true"])),
            mem_limit=self.cfg.get("mem_limit", "256m"),
            pids_limit=int(self.cfg.get("pids_limit", 200)),
            user=self.cfg.get("user", "1000:1000"),
            auto_remove=False,
            environment={"TERM": term, "HOME": "/home/admin", "USER": "admin"},
            tmpfs=dict(self.cfg.get("tmpfs", {})),
            hostname="corp-server-01",
        )
        cpus = self.cfg.get("cpus")
        if cpus is not None:
            try:
                kw["nano_cpus"] = int(float(cpus) * 1e9)
            except (TypeError, ValueError):
                pass
        return kw

    def _watchdog_loop(self):
        while not self._stop.wait(5.0):
            now = time.time()
            expired = []
            with self._lock:
                for sid, s in self.sessions.items():
                    if not s.closed and now - s.started_at > self.session_ttl:
                        expired.append(sid)
            for sid in expired:
                self.log.warning("sandbox TTL aşıldı (%ds), kapatılıyor: %s",
                                 self.session_ttl, sid)
                self.destroy(sid)
