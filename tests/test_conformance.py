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
    monkeypatch.setattr(
        ConformanceSuite, "_probe_cgroup_behavior", lambda self: probes[3]
    )
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


def test_grade_report_scores_named_guarantees(monkeypatch):
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_python_build",
        lambda self: ProbeResult(
            "python_build",
            True,
            True,
            "python ok",
            {"py_gil_disabled": True},
        ),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_bpf_availability",
        lambda self: ProbeResult("bpf_availability", True, True, "bpf ok", {}),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_cgroup_behavior",
        lambda self: ProbeResult("cgroup_behavior", True, True, "cgroup ok", {}),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_policy_enforcement",
        lambda self: ProbeResult("policy_enforcement", True, True, "policy ok", {}),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_timeout_and_kill_behavior",
        lambda self: ProbeResult(
            "timeout_and_kill_behavior", True, True, "quota ok", {}
        ),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_ebpf_lsm",
        lambda self, bpf_availability=None: ProbeResult(
            "ebpf_lsm", True, True, "lsm ok", {}
        ),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_landlock_fallback",
        lambda self, ebpf_lsm_active=False: ProbeResult(
            "landlock_fallback", False, False, "no landlock", {}
        ),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_no_gil_extension_safety",
        lambda self, python_build=None, policy_enforcement=None: ProbeResult(
            "no_gil_extension_safety", True, True, "native loaders blocked", {}
        ),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_broker_crypto",
        lambda self: ProbeResult("broker_crypto", True, True, "crypto ok", {}),
    )
    monkeypatch.setattr(
        ConformanceSuite,
        "_probe_crash_isolation",
        lambda self: ProbeResult("crash_isolation", True, True, "crash ok", {}),
    )
    monkeypatch.setattr("pyisolate.conformance.sys.version_info", (3, 13, 0))

    report = ConformanceSuite().grade()
    payload = report.to_dict()

    assert report.score == 7
    assert report.max_score == 8
    assert payload["active_guarantees"] == [
        "free_threading",
        "ebpf_lsm",
        "cgroup_v2",
        "no_gil_extension_safety",
        "broker_crypto",
        "quota_enforcement",
        "crash_isolation",
    ]
    assert payload["inactive_guarantees"] == ["landlock_fallback"]
    assert [component["label"] for component in payload["components"]] == [
        "free-threading",
        "eBPF-LSM",
        "cgroup v2",
        "Landlock fallback",
        "no-GIL extension safety",
        "broker crypto",
        "quota enforcement",
        "crash isolation",
    ]


def test_conformance_cli_grade(monkeypatch, capsys):
    monkeypatch.setattr(
        ConformanceSuite,
        "grade",
        lambda self: type(
            "FakeGrade",
            (),
            {"to_json": lambda _self: json.dumps({"score": 6, "max_score": 8})},
        )(),
    )

    exit_code = main(["--grade"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert json.loads(out) == {"score": 6, "max_score": 8}
