"""Shared test fixtures.

The test-vectors.json file lives at the AWSP package root, four levels up
from this tests/ directory:

    packages/awsp/test-vectors.json
    packages/awsp/reference/python/tests/conftest.py

We resolve it via pathlib so both `pytest tests/` and `python -m pytest`
from anywhere find the same vectors file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# tests/ -> python/ -> reference/ -> awsp/ -> test-vectors.json
_VECTORS_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent / "test-vectors.json"
)


@pytest.fixture(scope="session")
def vectors_path() -> Path:
    return _VECTORS_PATH


@pytest.fixture(scope="session")
def vectors_file() -> dict[str, Any]:
    with _VECTORS_PATH.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    return data


@pytest.fixture(scope="session")
def vectors(vectors_file: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = vectors_file["vectors"]
    return result
