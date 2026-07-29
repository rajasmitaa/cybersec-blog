"""
Unit tests for services.geoip

Run with: pytest waf/tests_services/test_geoip.py -v
"""

import sys
import os
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.services.geoip import (
    is_private_ip,
    lookup_ip,
    GeoLookupResult,
    _get_reader,
    close_readers,
)
import waf.services.geoip as geoip_module


def test_private_ip_detected():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("127.0.0.1") is True


def test_public_ip_not_private():
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_invalid_ip_treated_as_private():
    assert is_private_ip("not-an-ip") is True
    assert is_private_ip("") is True


def test_empty_ip_returns_not_found():
    result = lookup_ip("")
    assert result.found is False
    assert "empty" in result.reason.lower()


def test_private_ip_skips_lookup_entirely():
    result = lookup_ip("192.168.1.1")
    assert result.found is False
    assert result.is_private is True


def test_missing_geoip2_package_returns_not_found(monkeypatch):
    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", False)
    result = lookup_ip("8.8.8.8")
    assert result.found is False
    assert "not installed" in result.reason.lower()


def test_missing_database_file_returns_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", True)
    geoip_module._reader_cache.clear()
    nonexistent_path = str(tmp_path / "does_not_exist.mmdb")
    result = lookup_ip("8.8.8.8", db_path=nonexistent_path)
    assert result.found is False
    assert "not available" in result.reason.lower()


def test_successful_lookup_with_mocked_reader(monkeypatch, tmp_path):
    fake_db = tmp_path / "fake.mmdb"
    fake_db.write_text("not a real mmdb, just needs to exist")

    mock_response = MagicMock()
    mock_response.country.iso_code = "US"
    mock_response.country.name = "United States"
    mock_response.city.name = "Mountain View"
    mock_response.location.latitude = 37.4056
    mock_response.location.longitude = -122.0775

    mock_reader = MagicMock()
    mock_reader.city.return_value = mock_response

    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", True)
    geoip_module._reader_cache.clear()
    monkeypatch.setattr(geoip_module, "_get_reader", lambda db_path: mock_reader)

    result = lookup_ip("8.8.8.8", db_path=str(fake_db))
    assert result.found is True
    assert result.country_code == "US"
    assert result.country_name == "United States"
    assert result.city == "Mountain View"
    assert result.latitude == 37.4056
    assert result.longitude == -122.0775


def test_address_not_found_in_database(monkeypatch, tmp_path):
    import geoip2.errors as real_errors_module

    fake_db = tmp_path / "fake.mmdb"
    fake_db.write_text("placeholder")

    mock_reader = MagicMock()
    mock_reader.city.side_effect = real_errors_module.AddressNotFoundError("not found")

    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", True)
    geoip_module._reader_cache.clear()
    monkeypatch.setattr(geoip_module, "_get_reader", lambda db_path: mock_reader)

    result = lookup_ip("8.8.8.8", db_path=str(fake_db))
    assert result.found is False
    assert "not found" in result.reason.lower()


def test_unexpected_lookup_error_handled_gracefully(monkeypatch, tmp_path):
    fake_db = tmp_path / "fake.mmdb"
    fake_db.write_text("placeholder")

    mock_reader = MagicMock()
    mock_reader.city.side_effect = RuntimeError("something broke")

    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", True)
    geoip_module._reader_cache.clear()
    monkeypatch.setattr(geoip_module, "_get_reader", lambda db_path: mock_reader)

    result = lookup_ip("8.8.8.8", db_path=str(fake_db))
    assert result.found is False
    assert "lookup failed" in result.reason.lower()


def test_get_reader_returns_none_when_geoip2_unavailable(monkeypatch):
    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", False)
    assert _get_reader("some/path.mmdb") is None


def test_get_reader_returns_none_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", True)
    geoip_module._reader_cache.clear()
    nonexistent_path = str(tmp_path / "missing.mmdb")
    assert _get_reader(nonexistent_path) is None


def test_get_reader_caches_across_calls(monkeypatch, tmp_path):
    fake_db = tmp_path / "fake.mmdb"
    fake_db.write_text("placeholder")

    mock_reader_instance = MagicMock()
    mock_reader_class = MagicMock(return_value=mock_reader_instance)

    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", True)
    geoip_module._reader_cache.clear()
    monkeypatch.setattr(geoip_module.geoip2.database, "Reader", mock_reader_class)

    first = _get_reader(str(fake_db))
    second = _get_reader(str(fake_db))

    assert first is mock_reader_instance
    assert second is mock_reader_instance
    mock_reader_class.assert_called_once()  # only opened once, second call used the cache


def test_close_readers_clears_cache(monkeypatch, tmp_path):
    fake_db = tmp_path / "fake.mmdb"
    fake_db.write_text("placeholder")

    mock_reader_instance = MagicMock()
    monkeypatch.setattr(geoip_module, "GEOIP2_AVAILABLE", True)
    geoip_module._reader_cache.clear()
    geoip_module._reader_cache[str(fake_db)] = mock_reader_instance

    close_readers()

    assert geoip_module._reader_cache == {}
    mock_reader_instance.close.assert_called_once()


def test_close_readers_handles_close_failure_gracefully(monkeypatch):
    broken_reader = MagicMock()
    broken_reader.close.side_effect = RuntimeError("already closed")
    geoip_module._reader_cache.clear()
    geoip_module._reader_cache["some/path.mmdb"] = broken_reader

    close_readers()  # should not raise
    assert geoip_module._reader_cache == {}
