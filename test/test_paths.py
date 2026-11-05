"""Path handling, which needs no federation and is where the two
implementations are most likely to disagree."""

from __future__ import annotations

import pytest

from pelicanfs_native.core import PelicanNativeFileSystem, _split_url

strip = PelicanNativeFileSystem._strip_protocol


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("pelican://example.org/ns/obj", ("pelican://example.org", "/ns/obj")),
        ("pelican+native://example.org/ns/obj", ("pelican://example.org", "/ns/obj")),
        ("pelican://example.org:8443/ns/obj", ("pelican://example.org:8443", "/ns/obj")),
        ("osdf:///ns/obj", ("pelican://osg-htc.org", "/ns/obj")),
        # The sloppy two-slash form, which readers mean as a path.
        ("osdf://ns/obj", ("pelican://osg-htc.org", "/ns/obj")),
        ("/ns/obj", (None, "/ns/obj")),
        ("example.org/ns/obj", ("pelican://example.org", "/ns/obj")),
    ],
)
def test_split_url(given, expected):
    assert _split_url(given) == expected


def test_split_url_rejects_foreign_scheme():
    with pytest.raises(ValueError, match="unsupported scheme"):
        _split_url("s3://bucket/key")


def test_split_url_requires_a_host():
    with pytest.raises(ValueError, match="names no federation host"):
        _split_url("pelican:///ns/obj")


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("pelican://example.org/ns/obj", "/ns/obj"),
        ("/ns/obj", "/ns/obj"),
        ("/ns/obj/", "/ns/obj"),
        ("", "/"),
        ("/", "/"),
    ],
)
def test_strip_protocol(given, expected):
    assert strip(given) == expected


def test_strip_protocol_is_idempotent():
    once = strip("pelican://example.org/ns/obj/")
    assert strip(once) == once


def test_kwargs_from_url_binds_the_federation():
    kwargs = PelicanNativeFileSystem._get_kwargs_from_urls("pelican+native://example.org/ns/obj")
    assert kwargs == {"federation_discovery_url": "pelican://example.org"}


def test_url_rejects_a_foreign_federation():
    fs = PelicanNativeFileSystem.__new__(PelicanNativeFileSystem)
    fs.discovery_url = "pelican://example.org"
    with pytest.raises(ValueError, match="bound to"):
        fs._url("pelican://other.example/ns/obj")
