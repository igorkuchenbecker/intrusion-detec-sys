"""Tests for configuration loading, validation and precedence."""

from __future__ import annotations

import pytest

from ids.config.settings import IDSConfig
from ids.core.exceptions import ConfigurationError


def test_defaults_are_conservative() -> None:
    config = IDSConfig()
    assert config.api_host == "127.0.0.1"  # not exposed to the network
    assert config.queue_max_size > 0
    assert config.retention_days == 7


@pytest.mark.parametrize(
    "kwargs",
    [
        {"queue_max_size": 0},
        {"port_scan_threshold": 0},
        {"traffic_window": -1},
        {"brute_force_threshold": 0},
        {"max_tracked_sources": 0},
        {"retention_days": -1},
        {"api_port": 70000},
        {"log_level": "LOUD"},
        {"port_scan_cooldown": -1},
    ],
)
def test_invalid_values_rejected(kwargs) -> None:
    with pytest.raises(ConfigurationError):
        IDSConfig(**kwargs)


def test_ephemeral_port_is_allowed() -> None:
    assert IDSConfig(api_port=0).api_port == 0


def test_unknown_keys_are_rejected() -> None:
    """A typo in a threshold name must fail loudly, not silently keep a default."""
    with pytest.raises(ConfigurationError):
        IDSConfig.from_mapping({"port_scan_treshold": 5})


def test_toml_sections_are_flattened(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[capture]\ninterface = "eth0"\n\n[detection]\nport_scan_threshold = 42\n',
        encoding="utf-8",
    )
    config = IDSConfig.from_toml(path)
    assert config.interface == "eth0"
    assert config.port_scan_threshold == 42


def test_missing_or_malformed_toml_is_reported(tmp_path) -> None:
    with pytest.raises(ConfigurationError):
        IDSConfig.from_toml(tmp_path / "absent.toml")

    bad = tmp_path / "bad.toml"
    bad.write_text("this is not = valid = toml", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        IDSConfig.from_toml(bad)


def test_environment_overrides_apply(monkeypatch) -> None:
    monkeypatch.setenv("IDS_PORT_SCAN_THRESHOLD", "99")
    monkeypatch.setenv("IDS_DASHBOARD_ENABLED", "false")
    config = IDSConfig.from_env(IDSConfig())
    assert config.port_scan_threshold == 99
    assert config.dashboard_enabled is False


def test_malformed_environment_value_is_reported(monkeypatch) -> None:
    monkeypatch.setenv("IDS_PORT_SCAN_THRESHOLD", "many")
    with pytest.raises(ConfigurationError):
        IDSConfig.from_env(IDSConfig())


def test_overrides_ignore_none_so_unset_flags_do_not_clobber() -> None:
    config = IDSConfig(interface="eth0").with_overrides(interface=None, api_port=9999)
    assert config.interface == "eth0"
    assert config.api_port == 9999
