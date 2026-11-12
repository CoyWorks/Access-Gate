"""Unprivileged single-purpose scheduler; SQLite transactions prevent duplicate runs."""
import json
import os
from pathlib import Path
import time
import threading
from .core import Store


def main():
    config=json.loads(Path(os.environ.get('ACCESS_GATE_CONFIG','/etc/access-gate/config.json')).read_text())
    store=Store(config['database'],config['pepper'])
    if not config.get('remote_gateway'):
        def subscriptions():
            while True:
                try:store.refresh_due_subscriptions()
                except Exception:pass  # A source/database outage must not stop code schedules.
                time.sleep(15)
        threading.Thread(target=subscriptions,name='blocklist-subscriptions',daemon=True).start()
    while True:
        store.run_schedules();time.sleep(15)


if __name__=='__main__':main()
