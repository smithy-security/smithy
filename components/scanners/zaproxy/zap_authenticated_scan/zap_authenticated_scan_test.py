import pytest
import tempfile
from urllib.parse import urlparse
import re

from zap_authenticated_scan import (
    ZapRunner,
    ZapInvalidTargetError,
    ZapInvalidAPIKeyError,
)


class DummyZap:
    class core:
        version = "2.11.1"

        @staticmethod
        def shutdown(apikey=None):
            return "OK"

    class context:
        @staticmethod
        def new_context(name):
            return "1"

        @staticmethod
        def context(name):
            return {"id": "1", "name": name}

    class automation:
        @staticmethod
        def run_plan(path):
            return "dummy-plan-id"

        @staticmethod
        def plan_progress(planid):
            # Simulate a finished plan
            return {"error": False, "finished": True, "info": "done"}


@pytest.fixture
def runner(monkeypatch):
    # Patch ZAPv2 to DummyZap
    monkeypatch.setattr(
        "zap_authenticated_scan.ZAPv2",
        lambda *a, **kw: DummyZap(),
    )
    return ZapRunner(api_key="testkey", target_url="http://example.com")


def test_invalid_target_url_raises():
    with pytest.raises(ZapInvalidTargetError):
        ZapRunner(api_key="testkey", target_url="not_a_url")


def test_invalid_api_key_raises():
    with pytest.raises(ZapInvalidAPIKeyError):
        ZapRunner(api_key="", target_url="http://example.com")


def test_context_creation(runner):
    runner.create_context()
    assert runner.context_id == "1"
    assert runner.context_name == "Default Context"


def test_add_authentication_to_scan_via_run_automation_framework_scan(
    monkeypatch, runner
):
    # Patch subprocess.Popen to avoid launching ZAP
    monkeypatch.setattr(
        "zap_authenticated_scan.subprocess",
        type(
            "DummySubprocess",
            (),
            {
                "Popen": lambda *a, **kw: type(
                    "Proc",
                    (),
                    {
                        "terminate": lambda self: None,
                        "wait": lambda self, timeout=None: 0,
                        "poll": lambda self: None,
                    },
                )()
            },
        ),
    )
    # Patch open to dummy
    monkeypatch.setattr(
        "builtins.open",
        lambda f, mode="r": type(
            "DummyFile",
            (),
            {
                "write": lambda self, x: None,
                "close": lambda self: None,
                "__enter__": lambda self: self,
                "__exit__": lambda self, *a: None,
            },
        )(),
    )
    runner.zap = DummyZap()
    runner.context_name = "Test Context"
    report_dir = tempfile.mkdtemp()
    target = "http://example.com"
    result = runner.run_automation_framework_scan(
        login_url=target,
        username="user",
        password="pass",
        filename="report.json",
        report_name="Test Report",
        report_title="Test Report Title",
        report_dir=report_dir,
        scan_duration=10,
        spider_duration=5,
    )
    ctx = result["env"]["contexts"][0]
    assert ctx["authentication"]["method"] == "browser"
    assert ctx["users"][0]["credentials"]["username"] == "user"
    assert ctx["users"][0]["credentials"]["password"] == "pass"
    assert ctx["users"][0]["enabled"] is True

    # Assert verification is set to autodetect
    assert ctx["authentication"]["verification"]["method"] == "autodetect"

    # Assert there is a requestor job
    requestor_jobs = [job for job in result["jobs"] if job.get("type") == "requestor"]
    assert (
        len(
            [
                job
                for job in requestor_jobs
                if job.get("parameters", {}).get("user") == "default-user"
            ]
        )
        == 1
    )
    assert any(
        requestor_jobs[0].get("requests", [{}])[0].get("url") == target
        for job in requestor_jobs
    )


def test_run_automation_framework_scan_baseline(monkeypatch, runner):
    # Patch subprocess.Popen to avoid launching ZAP
    monkeypatch.setattr(
        "zap_authenticated_scan.subprocess",
        type(
            "DummySubprocess",
            (),
            {
                "Popen": lambda *a, **kw: type(
                    "Proc",
                    (),
                    {
                        "terminate": lambda self: None,
                        "wait": lambda self, timeout=None: 0,
                        "poll": lambda self: None,
                    },
                )()
            },
        ),
    )
    # Patch open to dummy
    monkeypatch.setattr(
        "builtins.open",
        lambda f, mode="r": type(
            "DummyFile",
            (),
            {
                "write": lambda self, x: None,
                "close": lambda self: None,
                "__enter__": lambda self: self,
                "__exit__": lambda self, *a: None,
            },
        )(),
    )
    runner.zap = DummyZap()
    result = runner.run_automation_framework_scan(
        report_dir="/tmp",
        scan_duration=10,
        spider_duration=5,
    )
    # Assert the result is a dict (the parsed automation framework plan)
    assert isinstance(result, dict)
    # Check top-level keys
    assert "env" in result
    assert "jobs" in result
    # Check context configuration
    contexts = result["env"]["contexts"]
    assert isinstance(contexts, list)
    assert len(contexts) == 1
    context = contexts[0]

    # The target URL should be set correctly
    assert context["urls"] == [runner.target_url]
    # Include paths should contain the escaped netloc/path
    urlparsed = urlparse(runner.target_url)
    without_scheme = re.escape(f"{urlparsed.netloc}{urlparsed.path.rstrip('/')}")
    include_url = f".*{without_scheme}.*"
    assert include_url in context["includePaths"][0]
    # Exclude paths should be a list and contain global_exclude_paths
    assert isinstance(context["excludePaths"], list)
    # Check jobs configuration
    jobs = result["jobs"]
    assert any(job["type"] == "activeScan" for job in jobs)
    assert any(job["type"] == "spider" for job in jobs)
    assert any(job["type"] == "spiderAjax" for job in jobs)
    assert any(job["type"] == "report" for job in jobs)
    # Check that scan_duration and spider_duration are set
    for job in jobs:
        if job["type"] == "activeScan":
            assert job["parameters"]["maxScanDurationInMins"] == 10
        if job["type"] == "spider":
            assert job["parameters"]["maxDuration"] == 5
        if job["type"] == "spiderAjax":
            assert job["parameters"]["maxDuration"] == 5
        if job["type"] == "report":
            assert job["parameters"]["reportDir"] == "/tmp"
