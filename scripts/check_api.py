#!/usr/bin/env python3
"""Run API contract/runtime checks; missing validation extras are an error."""
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def main():
    try:
        import jsonschema
        import openapi_spec_validator
    except ImportError:
        print('Install tests/requirements-contract.txt in the development environment.',file=sys.stderr)
        return 2
    loader=unittest.TestLoader();suite=unittest.TestSuite()
    for pattern in ('test_api_contract.py','test_rest_api.py','test_api_responses.py'):
        suite.addTests(loader.discover(str(ROOT/'tests'),pattern=pattern))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and not result.skipped else 1

if __name__=='__main__':raise SystemExit(main())
