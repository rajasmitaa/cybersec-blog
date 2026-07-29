"""
geoip.py

Resolves an IP address to geographic location data (country, city,
coordinates) using a local MaxMind GeoLite2 database file -- no
external API calls at request time.

Why local-file over an external API:
    - A WAF sits in the critical path of every request; an external
      API call per-request adds latency and a hard dependency on a
      third party being up.
    - Free external geo-IP APIs are rate-limited and won't scale with
      real traffic.
    - Avoids leaking visitor/attacker IPs to a third-party service.
    - Works fully offline once the database file is downloaded.

Requires the free `geoip2` package (`pip install geoip2`) and a
GeoLite2-Country or GeoLite2-City .mmdb file from MaxMind
(https://dev.maxmind.com/geoip/geolite2-free-geolocation-data),
placed at a path you configure via GEOIP_DB_PATH or passed directly.

Design:
    - Never raises. Missing library, missing/corrupt database file,
      private/reserved IPs, or invalid IPs all resolve to a
      GeoLookupResult with found=False rather than throwing --
      callers (middleware, dashboard, logging) always get a usable
      object back.
    - The reader is opened once per process and cached, not
      re-opened per lookup -- MaxMind's reader is thread-safe for
      concurrent reads and expensive to keep re-opening.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False


DEFAULT_DB_PATH = os.environ.get("GEOIP_DB_PATH", "waf/data/GeoLite2-City.mmdb")

_reader_cache: dict = {}


@dataclass
class GeoLookupResult:
    ip: str
    found: bool
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_private: bool = False
    reason: str = ""


def is_private_ip(ip: str) -> bool:
    """True for loopback/private/reserved/link-local addresses --
    these will never resolve to a real location, so callers can skip
    the lookup and short-circuit early. Invalid IP strings are
    treated as "private" (i.e. not worth looking up) rather than
    raising.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _get_reader(db_path: str):
    """Open (or reuse a cached) geoip2 database reader for db_path.
    Returns None if geoip2 isn't installed or the file can't be
    opened -- never raises."""
    if not GEOIP2_AVAILABLE:
        return None
    if db_path in _reader_cache:
        return _reader_cache[db_path]
    if not os.path.isfile(db_path):
        return None
    try:
        reader = geoip2.database.Reader(db_path)
    except Exception:
        return None
    _reader_cache[db_path] = reader
    return reader


def lookup_ip(ip: str, db_path: str = DEFAULT_DB_PATH) -> GeoLookupResult:
    """The main entry point: resolve one IP to a GeoLookupResult.

    Never raises. Returns found=False with a `reason` explaining why
    for any failure case: private/invalid IP, geoip2 not installed,
    database file missing, or the IP simply not being in the
    database.
    """
    if not ip:
        return GeoLookupResult(ip=ip or "", found=False, reason="empty IP")

    if is_private_ip(ip):
        return GeoLookupResult(ip=ip, found=False, is_private=True, reason="private/reserved/invalid IP")

    if not GEOIP2_AVAILABLE:
        return GeoLookupResult(ip=ip, found=False, reason="geoip2 package not installed")

    reader = _get_reader(db_path)
    if reader is None:
        return GeoLookupResult(ip=ip, found=False, reason=f"GeoIP database not available at {db_path}")

    try:
        response = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return GeoLookupResult(ip=ip, found=False, reason="IP not found in GeoIP database")
    except Exception as exc:
        return GeoLookupResult(ip=ip, found=False, reason=f"lookup failed: {exc}")

    return GeoLookupResult(
        ip=ip,
        found=True,
        country_code=response.country.iso_code,
        country_name=response.country.name,
        city=response.city.name,
        latitude=response.location.latitude,
        longitude=response.location.longitude,
    )


def close_readers() -> None:
    """Close and clear all cached database readers. Mainly useful for
    clean shutdown or between test runs so file handles don't leak."""
    for reader in _reader_cache.values():
        try:
            reader.close()
        except Exception:
            pass
    _reader_cache.clear()
