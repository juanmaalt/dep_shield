import pytest
from unittest.mock import MagicMock, patch
import httpx

from src.scanners.osv import extract_severity, parse_vulnerabilities, query_vulnerabilities


class TestExtractSeverity:
    def test_from_severity_list(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        assert extract_severity(vuln) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_from_database_specific(self):
        vuln = {"severity": [], "database_specific": {"severity": "HIGH"}}
        assert extract_severity(vuln) == "HIGH"

    def test_no_severity(self):
        assert extract_severity({}) is None

    def test_severity_list_takes_priority_over_db_specific(self):
        vuln = {
            "severity": [{"score": "CRITICAL_SCORE"}],
            "database_specific": {"severity": "LOW"},
        }
        assert extract_severity(vuln) == "CRITICAL_SCORE"

    def test_empty_severity_list_falls_back_to_db_specific(self):
        vuln = {"severity": [], "database_specific": {"severity": "MEDIUM"}}
        assert extract_severity(vuln) == "MEDIUM"

    def test_missing_score_key_returns_none(self):
        vuln = {"severity": [{"type": "CVSS_V3"}]}
        assert extract_severity(vuln) is None


class TestParseVulnerabilities:
    def test_empty_response(self):
        assert parse_vulnerabilities({}) == []

    def test_empty_vulns_list(self):
        assert parse_vulnerabilities({"vulns": []}) == []

    def test_single_vulnerability(self):
        data = {
            "vulns": [
                {
                    "id": "GHSA-1234-5678-90ab",
                    "summary": "Remote code execution",
                    "details": "Detailed description",
                    "severity": [{"score": "CRITICAL"}],
                }
            ]
        }
        result = parse_vulnerabilities(data)
        assert len(result) == 1
        assert result[0].id == "GHSA-1234-5678-90ab"
        assert result[0].summary == "Remote code execution"
        assert result[0].severity == "CRITICAL"
        assert result[0].details == "Detailed description"

    def test_multiple_vulnerabilities(self):
        data = {
            "vulns": [
                {"id": "CVE-2023-0001", "summary": "Vuln 1"},
                {"id": "CVE-2023-0002", "summary": "Vuln 2"},
            ]
        }
        result = parse_vulnerabilities(data)
        assert len(result) == 2
        assert {v.id for v in result} == {"CVE-2023-0001", "CVE-2023-0002"}

    def test_missing_fields_use_defaults(self):
        result = parse_vulnerabilities({"vulns": [{}]})
        assert len(result) == 1
        assert result[0].id == "Unknown"
        assert result[0].summary == "No summary available"
        assert result[0].severity is None
        assert result[0].details is None


class TestQueryVulnerabilities:
    def test_successful_query(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulns": [{"id": "CVE-2023-0001", "summary": "Test vuln"}]
        }

        with patch("src.scanners.osv.httpx.post", return_value=mock_response):
            result = query_vulnerabilities("requests", "2.28.0")

        assert len(result) == 1
        assert result[0].id == "CVE-2023-0001"

    def test_http_error_returns_empty_list(self):
        with patch("src.scanners.osv.httpx.post", side_effect=httpx.HTTPError("connection failed")):
            result = query_vulnerabilities("requests", "2.28.0")

        assert result == []

    def test_query_without_version_omits_version_field(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulns": []}

        with patch("src.scanners.osv.httpx.post", return_value=mock_response) as mock_post:
            query_vulnerabilities("requests", None)

        payload = mock_post.call_args.kwargs["json"]
        assert "version" not in payload

    def test_query_with_version_includes_version_field(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulns": []}

        with patch("src.scanners.osv.httpx.post", return_value=mock_response) as mock_post:
            query_vulnerabilities("requests", "2.28.0")

        payload = mock_post.call_args.kwargs["json"]
        assert payload["version"] == "2.28.0"

    def test_package_name_included_in_payload(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulns": []}

        with patch("src.scanners.osv.httpx.post", return_value=mock_response) as mock_post:
            query_vulnerabilities("numpy", "1.21.0")

        payload = mock_post.call_args.kwargs["json"]
        assert payload["package"]["name"] == "numpy"
        assert payload["package"]["ecosystem"] == "PyPI"
