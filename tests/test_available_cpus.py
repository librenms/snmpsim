import argparse

import pytest

from snmpsim import utils
from snmpsim.commands import responder_lite


@pytest.fixture
def cgroup(tmp_path, monkeypatch):
    """Fake cgroup v2 tree with this process in /docker/abc"""
    proc_cgroup = tmp_path / "proc_cgroup"
    proc_cgroup.write_text("0::/docker/abc\n")

    real_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/self/cgroup":
            path = proc_cgroup
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)

    root = tmp_path / "cgroup"
    (root / "docker" / "abc").mkdir(parents=True)

    return root


def test_no_limit(cgroup):
    (cgroup / "docker" / "abc" / "cpu.max").write_text("max 100000\n")

    assert utils._cgroup_cpu_limit(str(cgroup)) is None


def test_v2_limit(cgroup):
    (cgroup / "docker" / "abc" / "cpu.max").write_text("150000 100000\n")

    assert utils._cgroup_cpu_limit(str(cgroup)) == 1.5


def test_v2_ancestor_limit_wins_when_lower(cgroup):
    (cgroup / "docker" / "abc" / "cpu.max").write_text("400000 100000\n")
    (cgroup / "docker" / "cpu.max").write_text("200000 100000\n")

    assert utils._cgroup_cpu_limit(str(cgroup)) == 2


def test_v1_limit(cgroup):
    (cgroup / "cpu").mkdir()
    (cgroup / "cpu" / "cpu.cfs_quota_us").write_text("300000\n")
    (cgroup / "cpu" / "cpu.cfs_period_us").write_text("100000\n")

    assert utils._cgroup_cpu_limit(str(cgroup)) == 3


def test_v1_unlimited(cgroup):
    (cgroup / "cpu").mkdir()
    (cgroup / "cpu" / "cpu.cfs_quota_us").write_text("-1\n")
    (cgroup / "cpu" / "cpu.cfs_period_us").write_text("100000\n")

    assert utils._cgroup_cpu_limit(str(cgroup)) is None


@pytest.mark.parametrize(
    "limit, affinity, expected", [(None, 8, 8), (1.5, 8, 2), (0.2, 8, 1), (16, 4, 4)]
)
def test_available_cpus(monkeypatch, limit, affinity, expected):
    monkeypatch.setattr(utils, "_cgroup_cpu_limit", lambda: limit)
    monkeypatch.setattr(utils.os, "sched_getaffinity", lambda pid: range(affinity))

    assert utils.available_cpus() == expected


@pytest.mark.parametrize(
    "value, expected", [("1", 1), ("4", 4), ("0", 3), ("auto", 3), (" AUTO ", 3)]
)
def test_parse_workers(monkeypatch, value, expected):
    monkeypatch.setattr(utils, "available_cpus", lambda: 3)

    assert responder_lite.parse_workers(value) == expected


@pytest.mark.parametrize("value", ["-1", "many", ""])
def test_parse_workers_rejects(value):
    with pytest.raises(argparse.ArgumentTypeError):
        responder_lite.parse_workers(value)
