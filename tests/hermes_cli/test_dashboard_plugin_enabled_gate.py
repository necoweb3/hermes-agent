"""Tests for the plugins.enabled trust gate in the dashboard plugin loader."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hermes_cli import web_server


@pytest.fixture(autouse=True)
def _reset_plugin_cache():
    """Bust the plugin cache before and after each test."""
    web_server._dashboard_plugins_cache = None
    yield
    web_server._dashboard_plugins_cache = None


class TestMountApiRoutesChecksPluginsEnabled:
    def _payload_plugin(self, tmp_path: Path, name: str = "custom", source: str = "user", api_file: str = "api.py") -> dict:
        plugin_dir = tmp_path / "plugins" / name
        dashboard_dir = plugin_dir / "dashboard"
        dashboard_dir.mkdir(parents=True, exist_ok=True)
        (dashboard_dir / api_file).write_text("router = None\n", encoding="utf-8")
        return {
            "name": name,
            "label": name.capitalize(),
            "source": source,
            "_dir": str(dashboard_dir),
            "_api_file": api_file,
        }

    def test_user_plugin_when_enabled_is_imported(self, tmp_path):
        plugin = self._payload_plugin(tmp_path, name="custom", source="user")
        web_server._dashboard_plugins_cache = [plugin]
        with patch("hermes_cli.plugins._get_enabled_plugins", return_value={"custom"}), \
             patch("hermes_cli.plugins._get_disabled_plugins", return_value=set()), \
             patch("importlib.util.spec_from_file_location") as spec:
            spec.return_value = None
            web_server._mount_plugin_api_routes()
        assert spec.call_count == 1
        called_path = Path(spec.call_args.args[1])
        assert called_path.name == "api.py"

    def test_user_plugin_when_not_in_enabled_is_ignored(self, tmp_path):
        plugin = self._payload_plugin(tmp_path, name="custom", source="user")
        web_server._dashboard_plugins_cache = [plugin]
        with patch("hermes_cli.plugins._get_enabled_plugins", return_value={"other"}), \
             patch("hermes_cli.plugins._get_disabled_plugins", return_value=set()), \
             patch("importlib.util.spec_from_file_location") as spec:
            spec.return_value = None
            web_server._mount_plugin_api_routes()
        assert spec.call_count == 0

    def test_user_plugin_when_disabled_wins_over_enabled(self, tmp_path):
        plugin = self._payload_plugin(tmp_path, name="custom", source="user")
        web_server._dashboard_plugins_cache = [plugin]
        with patch("hermes_cli.plugins._get_enabled_plugins", return_value={"custom"}), \
             patch("hermes_cli.plugins._get_disabled_plugins", return_value={"custom"}), \
             patch("importlib.util.spec_from_file_location") as spec:
            spec.return_value = None
            web_server._mount_plugin_api_routes()
        assert spec.call_count == 0

    def test_bundled_plugin_always_imported_regardless_of_enabled_list(self, tmp_path):
        plugin = self._payload_plugin(tmp_path, name="achievements", source="bundled")
        web_server._dashboard_plugins_cache = [plugin]
        with patch("hermes_cli.plugins._get_enabled_plugins", return_value={"other"}), \
             patch("hermes_cli.plugins._get_disabled_plugins", return_value={"achievements"}), \
             patch("importlib.util.spec_from_file_location") as spec:
            spec.return_value = None
            web_server._mount_plugin_api_routes()
        assert spec.call_count == 1
        called_path = Path(spec.call_args.args[1])
        assert called_path.name == "api.py"
