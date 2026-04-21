import json

from pyisolate.conformance import ConformanceSuite, ProbeResult, main


def test_suite_aggregates_required_and_optional(monkeypatch):
    probes = [
        ProbeResult("python_build", True, True, "ok", {}),
        ProbeResult("kernel_capabilities", False, False, "warn", {}),
        ProbeResult("bpf_availability", True, True, "ok", {}),
        ProbeResult("cgroup_behavior", True, True, "ok", {}),
        ProbeResult("policy_enforcement", True, True, "ok", {}),
        ProbeResult("timeout_and_kill_behavior", True, True, "ok", {}),
    ]

    monkeypatch.setattr(ConformanceSuite, "_probe_python_build", lambda self: probes[0])
    monkeypatch.setattr(
        ConformanceSuite, "_probe_kernel_capabilities", lambda self: probes[1]
    )
    monkeypatch.setattr(
        ConformanceSuite, "_probe_bpf_availability", lambda self: probes[2]
    )
    monkeypatch.setattr(ConformanceSuite, "_probe_cgroup_behavior", lambda self: probes[3])
    monkeypatch.setattr(
        ConformanceSuite, "_probe_policy_enforcement", lambda self: probes[4]
    )
    monkeypatch.setattr(
        ConformanceSuite, "_probe_timeout_and_kill_behavior", lambda self: probes[5]
    )

    report = ConformanceSuite().run()

    assert report.passed is True
    assert report.required_passed == 5
    assert report.required_total == 5
    assert report.optional_passed == 0
    assert report.optional_total == 1


def test_cli_json_output(monkeypatch, capsys):
    monkeypatch.setattr(
        ConformanceSuite,
        "run",
        lambda self: type(
            "FakeReport",
            (),
            {
                "passed": True,
                "to_json": lambda _self: json.dumps({"passed": True}),
            },
        )(),
    )

    exit_code = main(["--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert json.loads(out)["passed"] is True
