import os
import signal
import socket
import subprocess
import sys
import time

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(TESTS_DIR, "data", "UPS")

p_mod = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def query(port, oid="1.3.6.1.2.1.1.1.0"):
    pdu = p_mod.GetRequestPDU()
    p_mod.apiPDU.set_defaults(pdu)
    p_mod.apiPDU.set_varbinds(pdu, [(univ.ObjectIdentifier(oid), p_mod.Null(""))])

    msg = p_mod.Message()
    p_mod.apiMessage.set_defaults(msg)
    p_mod.apiMessage.set_community(msg, "public")
    p_mod.apiMessage.set_pdu(msg, pdu)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(encoder.encode(msg), ("127.0.0.1", port))
        data, _ = sock.recvfrom(65535)

    msg, _ = decoder.decode(data, asn1Spec=p_mod.Message())

    return p_mod.apiPDU.get_varbinds(p_mod.apiMessage.get_pdu(msg))


RESPONDERS = ["snmpsim.commands.responder_lite", "snmpsim.commands.responder"]


def daemonize(tmp_path, port, data_dir=DATA_DIR, module=RESPONDERS[0], **kwargs):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            module,
            f"--data-dir={data_dir}",
            f"--cache-dir={tmp_path / 'cache'}",
            f"--agent-udpv4-endpoint=127.0.0.1:{port}",
            "--log-level=error",
            f"--logging-method=file:{tmp_path / 'snmpsim.log'}",
            "--daemonize",
            f"--pid-file={tmp_path / 'snmpsim.pid'}",
        ],
        capture_output=True,
        timeout=60,
        **kwargs,
    )


def read_pid(tmp_path):
    try:
        with open(tmp_path / "snmpsim.pid") as f:
            return int(f.read())

    except (OSError, ValueError):
        return None


def stop(pid):
    try:
        os.kill(pid, signal.SIGTERM)

    except ProcessLookupError:
        return

    deadline = time.monotonic() + 10

    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)

        except ProcessLookupError:
            return

        time.sleep(0.05)

    os.kill(pid, signal.SIGKILL)


@pytest.fixture
def daemon_cleanup(tmp_path):
    yield

    # the daemon is detached from the test process, never leak it
    pid = read_pid(tmp_path)

    if pid:
        stop(pid)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
@pytest.mark.parametrize("module", RESPONDERS)
def test_daemonize_returns_when_ready(tmp_path, daemon_cleanup, module):
    port = free_port()

    rc = daemonize(tmp_path, port, module=module)

    assert rc.returncode == 0, rc.stderr.decode()

    # answered right away, without polling for readiness
    var_binds = query(port)

    assert str(var_binds[0][1]).startswith("APC Web/SNMP Management Card")

    pid = read_pid(tmp_path)

    assert pid is not None
    os.kill(pid, 0)
    assert "snmpsim" in open(f"/proc/{pid}/cmdline").read()

    stop(pid)

    assert not (tmp_path / "snmpsim.pid").exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
def test_daemonize_relative_data_dir(tmp_path, daemon_cleanup):
    port = free_port()

    rc = daemonize(tmp_path, port, data_dir=os.path.join("data", "UPS"), cwd=TESTS_DIR)

    assert rc.returncode == 0, rc.stderr.decode()

    var_binds = query(port)

    assert str(var_binds[0][1]).startswith("APC Web/SNMP Management Card")


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
@pytest.mark.parametrize("module", RESPONDERS)
def test_daemonize_fails_when_port_in_use(tmp_path, daemon_cleanup, module):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        rc = daemonize(tmp_path, port, module=module)

    assert rc.returncode != 0
    assert b"Failed to bind UDP endpoint" in rc.stderr

    # the failed daemon removes its pid file on the way out
    deadline = time.monotonic() + 5

    while (tmp_path / "snmpsim.pid").exists() and time.monotonic() < deadline:
        time.sleep(0.05)

    assert not (tmp_path / "snmpsim.pid").exists()
