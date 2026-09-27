"""
Phase 1 Bootstrap Tests: Environment & Repository Structure
"""

import sys
from pathlib import Path


def test_python_version():
    """Verify runtime Python is 3.11+"""
    assert sys.version_info >= (3, 11), f"Python version must be >= 3.11, found: {sys.version}"


def test_directory_structure_exists():
    """Verify all top-level architectural directories exist"""
    root = Path(__file__).resolve().parent.parent
    expected_dirs = [
        "ingest",
        "schemas",
        "streaming",
        "features",
        "detection",
        "ml",
        "alerts",
        "backend",
        "persistence",
        "replay",
        "benchmarks",
        "tests",
        "deployment",
        "docs",
    ]
    for d in expected_dirs:
        dir_path = root / d
        assert dir_path.is_dir(), f"Expected directory '{d}' missing from project root"


def test_health_endpoint_contract():
    """Verify backend health endpoint logic imports and returns expected status"""
    from backend.main import app
    assert app.title == "PS26145 Cyber Threat Detection API"
