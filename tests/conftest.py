"""Pytest ortak yapılandırması ve test fikstürleri."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Gerçek Gemini API çağrısı yapan @pytest.mark.live testlerini etkinleştirir.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-live"):
        return
    skip_live = pytest.mark.skip(reason="Canlı API testi varsayılan olarak atlandı (--run-live ile çalıştırın).")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


@pytest.fixture(autouse=True)
def _reset_api_state() -> None:
    """Her testten önce hız sınırlayıcıyı ve tarama durumunu temizler."""
    import llm_core
    from main import ScanStatusSnapshot, rate_limiter, scan_manager

    rate_limiter.reset()
    with scan_manager._lock:
        scan_manager._state = ScanStatusSnapshot()
    llm_core._cached_client = None
    llm_core._cached_api_key = None
