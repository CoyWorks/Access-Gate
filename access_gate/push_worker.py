"""Unprivileged notification delivery; no polling of the private portal from a phone."""
import json
import os
from pathlib import Path
import time
from .core import Store


def main():
    config=json.loads(Path(os.environ.get('ACCESS_GATE_CONFIG','/etc/access-gate/config.json')).read_text())
    store=Store(config['database'],config['pepper'])
    while True:
        store.deliver_push(config);time.sleep(2)


if __name__=='__main__':main()
