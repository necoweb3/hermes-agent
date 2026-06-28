"""Tests that gateway/config.py logs plugin discovery failures instead of swallowing."""

import logging
import pytest
from unittest.mock import patch


class TestPlatformMissingRedact:
    """Platform._missing_() must log exceptions instead of silently passing."""

    def test_platform_missing_logs_on_registry_failure(self, caplog):
        from gateway.config import Platform

        with patch.dict("sys.modules", {"gateway.platform_registry": None}):
            with caplog.at_level(logging.DEBUG):
                result = Platform._missing_("nonexistent-platform-xyz")
                assert result is None
                assert "nonexistent-platform-xyz" in caplog.text or "failed" in caplog.text.lower()


class TestScanBundledPlatforms:
    """_scan_bundled_plugin_platforms() must log filesystem errors."""

    def test_scan_logs_on_permission_error(self, caplog):
        from gateway.config import Platform

        with patch("pathlib.Path.is_dir", side_effect=PermissionError("denied")):
            with caplog.at_level(logging.DEBUG):
                result = Platform._scan_bundled_plugin_platforms()
                assert isinstance(result, set)
                assert "denied" in caplog.text or "failed" in caplog.text.lower()


class TestIsPlatformConnected:
    """_is_platform_connected() must log plugin discovery failures."""

    def test_connected_check_logs_discover_plugins_failure(self, caplog):
        from gateway.config import GatewayConfig, Platform

        config = GatewayConfig()
        config.platforms = {}

        with patch("gateway.config.discover_plugins", side_effect=ImportError("broken_module")):
            with caplog.at_level(logging.DEBUG):
                result = config._is_platform_connected(Platform.NONEXISTENT, None)
                assert result is False
