#!/usr/bin/env python3
"""SSH Honeypot Docker entrypoint — sadece SSH + sandbox başlatır."""
import signal
import sys
import time

import yaml

sys.path.insert(0, "/app")

from logger import HoneypotLogger
from alert_engine import AlertEngine
from sandbox_manager import SandboxManager
from ssh_honeypot import SSHHoneypot

with open("/app/config.yaml", encoding="utf-8") as f:
    config = yaml.safe_load(f)

hp_logger = HoneypotLogger(config)
alert_engine = AlertEngine(config, hp_logger)
sandbox_manager = SandboxManager(config, hp_logger)
sandbox_manager.start()

ssh = SSHHoneypot(
    config, hp_logger,
    alert_engine.process_alert,
    sandbox_manager=sandbox_manager,
    alert_engine=alert_engine,
)
ssh.start()


def shutdown(sig, frame):
    ssh.stop()
    sandbox_manager.stop()
    sys.exit(0)


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

while True:
    time.sleep(1)
