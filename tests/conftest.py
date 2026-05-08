"""Shared test fixtures.

The spec/ directory is vendored at the repository root, one level above this conftest.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = REPO_ROOT / "spec"
VECTORS_DIR = SPEC_DIR / "test-vectors"


@pytest.fixture(scope="session")
def vectors_dir() -> Path:
    assert VECTORS_DIR.is_dir(), f"test vectors not found at {VECTORS_DIR}"
    return VECTORS_DIR


@pytest.fixture(scope="session")
def schema() -> dict:
    schema_path = SPEC_DIR / "ai-evidence-envelope-v1.schema.json"
    return json.loads(schema_path.read_text())
