"""Tests for patchscope.tools.nvd_client."""

import pytest
from patchscope.tools.nvd_client import _validate_cve_id, fetch_cve_data, extract_patch_urls


class TestValidateCveId:
    def test_valid(self):
        assert _validate_cve_id("CVE-2023-32233") == "CVE-2023-32233"

    def test_lowercase(self):
        assert _validate_cve_id("cve-2023-32233") == "CVE-2023-32233"

    def test_strips_whitespace(self):
        assert _validate_cve_id("  CVE-2023-32233  ") == "CVE-2023-32233"

    def test_rejects_bad_format(self):
        with pytest.raises(ValueError):
            _validate_cve_id("NOT-A-CVE")

    def test_rejects_short_number(self):
        with pytest.raises(ValueError):
            _validate_cve_id("CVE-2023-12")  # need at least 4 digits


class TestFetchCveData:
    """Integration tests — require network access."""

    def test_known_cve(self):
        data = fetch_cve_data("CVE-2023-32233")
        assert data["cve_id"] == "CVE-2023-32233"
        assert len(data["description"]) > 0
        assert isinstance(data["references"], list)
        assert data["severity"] is not None

    def test_unknown_cve(self):
        with pytest.raises(ValueError, match="not found"):
            fetch_cve_data("CVE-1999-00000")


class TestExtractPatchUrls:
    def test_linux_kernel_cve_has_patches(self):
        """CVE-2023-32233: Linux kernel nf_tables use-after-free — has GitHub commit."""
        result = extract_patch_urls("CVE-2023-32233")
        assert result["cve_id"] == "CVE-2023-32233"
        assert len(result["patch_urls"]) > 0
        for url in result["patch_urls"]:
            assert "github.com" in url
            assert "/commit/" in url
