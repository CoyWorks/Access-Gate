"""Unprivileged single-purpose scheduler; SQLite transactions prevent duplicate runs."""
import json
import os
from pathlib import Path
import time
from .core import Store


def main():
    config=json.loads(Path(os.environ.get('ACCESS_GATE_CONFIG','/etc/access-gate/config.json')).read_text())
    store=Store(config['database'],config['pepper'])
    while True:
        store.run_schedules();time.sleep(15)


if __name__=='__main__':main()
