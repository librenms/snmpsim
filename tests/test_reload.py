import os
import shutil
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

DATA_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "UPS", "public.snmprec"
)
PORT = 1632

p_mod = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]


def get_request(community, request_id, oid):
    pdu = p_mod.GetRequestPDU()
    p_mod.apiPDU.set_defaults(pdu)
    p_mod.apiPDU.set_request_id(pdu, request_id)
    p_mod.apiPDU.set_varbinds(pdu, [(univ.ObjectIdentifier(oid), p_mod.Null(""))])

    msg = p_mod.Message()
    p_mod.apiMessage.set_defaults(msg)
    p_mod.apiMessage.set_community(msg, community)
    p_mod.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


def query(community, request_id=1, oid="1.3.6.1.2.1.1.1.0", timeout=2):
    """Value of the OID or None if there is no answer"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(get_request(community, request_id, oid), ("127.0.0.1", PORT))

        try:
            data, _ = sock.recvfrom(65535)

        except (socket.timeout, ConnectionRefusedError):
            return

    msg, _ = decoder.decode(data, asn1Spec=p_mod.Message())
    pdu = p_mod.apiMessage.get_pdu(msg)

    return str(p_mod.apiPDU.get_varbinds(pdu)[0][1])


def wait_for(proc, community, answered=True, timeout=30):
    deadline = time.monotonic() + timeout

    while True:
        value = query(community, timeout=0.5)

        if (value is not None) == answered:
            return value

        if proc.poll() is not None:
            pytest.fail(proc.stderr.read().decode())

        if time.monotonic() > deadline:
            pytest.fail(f"community {community} answered is not {answered}")


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="needs SIGHUP")
@pytest.mark.parametrize(
    "command",
    [
        ["snmpsim.commands.responder"],
        ["snmpsim.commands.responder_lite"],
        ["snmpsim.commands.responder_lite", "--workers=2"],
    ],
)
def test_sighup_reloads_data_files(tmp_path, command):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    shutil.copy(DATA_FILE, data_dir / "public.snmprec")

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            *command,
            f"--data-dir={data_dir}",
            f"--cache-dir={tmp_path / 'cache'}",
            f"--agent-udpv4-endpoint=127.0.0.1:{PORT}",
            "--log-level=error",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        assert wait_for(proc, "public").startswith("APC Web/SNMP Management Card")
        assert query("added", timeout=0.5) is None

        shutil.copy(DATA_FILE, data_dir / "added.snmprec")
        os.remove(data_dir / "public.snmprec")

        proc.send_signal(signal.SIGHUP)

        # with workers, every process must have reloaded
        for request_id in range(10):
            assert wait_for(proc, "added").startswith("APC Web/SNMP Management Card")
            assert wait_for(proc, "public", answered=False) is None

        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=10) == 0

    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
