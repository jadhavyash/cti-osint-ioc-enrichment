from cti_pipeline.core import validate, assess, enrich, build_report, executive_markdown, virustotal
import pytest


def test_validate():
    assert validate("8.8.8.8", "ip") == "8.8.8.8"
    assert validate("Example.COM", "domain") == "example.com"
    assert validate("https://example.com/a", "url") == "https://example.com/a"
    with pytest.raises(ValueError):
        validate("not an ip", "ip")
    with pytest.raises(ValueError):
        validate("file.exe", "hash")


def test_unknown_when_sources_unavailable():
    assert assess([{"status": "error", "source": "VirusTotal"}])["verdict"] == "unknown"


def test_malicious_overrides_no_detection():
    assert assess([{"status": "ok", "verdict": "malicious"}, {"status": "ok", "verdict": "no_detection"}])["priority"] == "high"


def test_missing_credentials_not_clean():
    result = enrich("8.8.8.8", "ip", config={})
    assert result["assessment"]["verdict"] == "unknown"


def test_report():
    result = enrich("8.8.8.8", "ip", config={})
    report = build_report([result])
    assert report["counts"]["unknown"] == 1
    assert "No detection does not mean" in executive_markdown(report)


class FakeResponse:
    status_code = 200
    headers = {}
    def json(self):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}}

class FakeSession:
    def request(self, *args, **kwargs):
        return FakeResponse()


def test_single_malicious_engine_not_clean():
    result = virustotal("example.com", "domain", "test", session=FakeSession())
    assert result["verdict"] == "suspicious"
