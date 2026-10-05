import contextlib
import os
import re
import shutil
import socket
import subprocess
import sys
import time

import pytest

from snmpsim import chaos

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "chaos")

NET_SNMP = all(shutil.which(tool) for tool in ("snmpget", "snmpwalk", "snmpbulkwalk"))

# net-snmp reports these on stderr when it gives up on an agent
ERRORS = re.compile(r"OID not increasing|Error in packet|Timeout|Reason:")

SCENARIOS = {
    "get": (
        "snmpget",
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.2.2.1.5.2",
        "1.3.6.1.2.1.2.2.1.10.3",
        "1.3.6.1.2.1.31.1.1.1.6.3",
        "1.3.6.1.2.1.2.2.1.2.2",
    ),
    "get-missing": ("snmpget", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.4.0"),
    "walk-table": ("snmpwalk", "1.3.6.1.2.1.2.2"),
    "walk-end": ("snmpwalk", "1.3.6.1.4.1.99999"),
    "bulkwalk-table": ("snmpbulkwalk", "1.3.6.1.2.1.2.2"),
    "bulkwalk-end": ("snmpbulkwalk", "1.3.6.1.4.1.99999"),
    "walk-table-Cc": ("snmpwalk", "-Cc", "1.3.6.1.2.1.2.2"),
    "walk-end-Cc": ("snmpwalk", "-Cc", "1.3.6.1.4.1.99999"),
    "bulkwalk-table-Cc": ("snmpbulkwalk", "-Cc", "1.3.6.1.2.1.2.2"),
    "bulkwalk-end-Cc": ("snmpbulkwalk", "-Cc", "1.3.6.1.4.1.99999"),
}

# quirks needing per-device settings: (scenario, extra flags, stderr)
UNSAFE = {
    "generr-for-missing": ("get-missing", (), "genErr"),
    "nosuchname-fails-pdu": ("get-missing", (), "noSuchName"),
    "wrap-at-end": ("walk-end", (), "OID not increasing"),
    "repeat-at-end": ("walk-end", (), "OID not increasing"),
    "unordered": ("bulkwalk-table", (), "OID not increasing"),
    "toobig": ("bulkwalk-table", ("-Cr20",), "tooBig"),
    "hang-after-bulk": ("bulkwalk-table", ("-Cr11",), "Timeout"),
    "max-oid": ("get", (), "tooBig"),
    "delay": ("get", ("-r0",), "Timeout"),
}


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def cache_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("cache")


@contextlib.contextmanager
def responder(cache_dir, log_path, *options):
    port = free_port()

    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "snmpsim.commands.responder_lite",
                f"--data-dir={DATA_DIR}",
                f"--cache-dir={cache_dir}",
                f"--agent-udpv4-endpoint=127.0.0.1:{port}",
                "--log-level=info",
                *options,
            ],
            stdout=subprocess.DEVNULL,
            stderr=log_file,
        )

    try:
        deadline = time.monotonic() + 30

        while "Listening at" not in log_path.read_text():
            if time.monotonic() > deadline or proc.poll() is not None:
                pytest.fail(log_path.read_text())

            time.sleep(0.05)

        yield port

    finally:
        proc.terminate()

        try:
            proc.wait(timeout=10)

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def run(port, scenario, *flags, timeout=30):
    tool, *args = SCENARIOS[scenario]

    try:
        result = subprocess.run(
            [tool, "-v2c", "-c", "public", "-On", "-t", "0.3", "-r", "3", *flags]
            + [f"127.0.0.1:{port}", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired:
        return None, "", "hung"

    return result.returncode, result.stdout, result.stderr


@pytest.fixture(scope="module")
def baseline(cache_dir, tmp_path_factory):
    log_path = tmp_path_factory.mktemp("baseline") / "responder.log"

    with responder(cache_dir, log_path) as port:
        return {scenario: run(port, scenario) for scenario in SCENARIOS}


def test_parse_quirks():
    assert chaos.parse_quirks("safe") == chaos.PRESETS["safe"]
    assert chaos.parse_quirks("all,-delay") == [
        name for name in chaos.QUIRKS if name != "delay"
    ]
    assert chaos.parse_quirks("safe,unordered,-duplicate") == [
        name for name in chaos.PRESETS["safe"] if name != "duplicate"
    ] + ["unordered"]

    with pytest.raises(ValueError):
        chaos.parse_quirks("safe,bogus")


def test_presets_cover_quirks():
    unsafe = [name for name in chaos.QUIRKS if name not in chaos.PRESETS["safe"]]

    assert sorted(unsafe) == sorted(UNSAFE)
    assert chaos.PRESETS["all"] == list(chaos.QUIRKS)


@pytest.mark.skipif(not NET_SNMP, reason="needs net-snmp command line tools")
@pytest.mark.parametrize("quirk", chaos.PRESETS["safe"])
def test_safe_quirk_survived_by_net_snmp(quirk, cache_dir, tmp_path, baseline):
    log_path = tmp_path / "responder.log"

    with responder(cache_dir, log_path, f"--chaos={quirk}", "--chaos-rate=1") as port:
        results = {scenario: run(port, scenario) for scenario in SCENARIOS}

    for scenario, (returncode, stdout, stderr) in results.items():
        assert returncode == baseline[scenario][0], (scenario, stdout, stderr)
        assert not ERRORS.search(stderr), (scenario, stdout, stderr)

    assert f'Chaos quirk "{quirk}"' in log_path.read_text()
    assert "Ignoring request" not in log_path.read_text()


@pytest.mark.skipif(not NET_SNMP, reason="needs net-snmp command line tools")
@pytest.mark.parametrize("quirk", sorted(UNSAFE))
def test_unsafe_quirk_breaks_net_snmp(quirk, cache_dir, tmp_path):
    scenario, flags, error = UNSAFE[quirk]
    log_path = tmp_path / "responder.log"

    with responder(cache_dir, log_path, f"--chaos={quirk}", "--chaos-rate=1") as port:
        returncode, stdout, stderr = run(port, scenario, *flags)

        if quirk == "unordered":
            # walking with -Cc is the workaround
            fixed = run(port, f"{scenario}-Cc")
            assert fixed[0] == 0 and not ERRORS.search(fixed[2]), fixed

        elif quirk == "delay":
            # the late response does arrive
            late = run(port, scenario, "-t", "3", "-r", "0")
            assert late[0] == 0 and not ERRORS.search(late[2]), late

    assert error in stderr, (returncode, stdout, stderr)
    assert f'Chaos quirk "{quirk}"' in log_path.read_text()
    assert "Ignoring request" not in log_path.read_text()


@pytest.mark.skipif(not NET_SNMP, reason="needs net-snmp command line tools")
def test_safe_preset_survived_by_net_snmp(cache_dir, tmp_path, baseline):
    log_path = tmp_path / "responder.log"

    with responder(cache_dir, log_path, "--chaos", "--chaos-rate=0.5") as port:
        for scenario in SCENARIOS:
            returncode, stdout, stderr = run(port, scenario)

            assert returncode == baseline[scenario][0], (scenario, stdout, stderr)
            assert not ERRORS.search(stderr), (scenario, stdout, stderr)

    assert "Chaos quirk" in log_path.read_text()
