from pyasn1.codec.ber import encoder
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.proto.api import v2c

from snmpsim import utils


def _encoded_varbinds_size(var_binds):
    pdu = v2c.ResponsePDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_varbinds(pdu, [])
    empty = len(encoder.encode(pdu))
    v2c.apiPDU.set_varbinds(pdu, var_binds)
    return len(encoder.encode(pdu)) - empty


def _var_binds(count, size):
    return [
        (rfc1902.ObjectName((1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 4, 0, i)),
         rfc1902.OctetString(b"\xff" * size))
        for i in range(1, count + 1)
    ]


def test_fit_var_binds_keeps_small_response():
    var_binds = _var_binds(10, 10)
    assert utils.fit_var_binds(var_binds, 65000) == var_binds


def test_fit_var_binds_truncates_oversized_response():
    # 50 x ~2.3KB values, like dot1qVlanCurrentEgressPorts, is > 64KB
    var_binds = _var_binds(50, 2295)
    fitted = utils.fit_var_binds(var_binds, 65000)

    assert 0 < len(fitted) < len(var_binds)
    assert fitted == var_binds[: len(fitted)]
    assert _encoded_varbinds_size(fitted) <= 65000
    assert _encoded_varbinds_size(var_binds[: len(fitted) + 1]) > 65000 - 32


def test_fit_var_binds_keeps_min_count():
    var_binds = _var_binds(3, 1000)
    assert utils.fit_var_binds(var_binds, 10, min_count=1) == var_binds[:1]


def test_fit_var_binds_handles_exceptions():
    var_binds = [
        (rfc1902.ObjectName("1.3.6.1.2.1.1.1.0"), rfc1905.EndOfMibView()),
        (rfc1902.ObjectName("1.3.6.1.2.1.1.1.0"), rfc1905.NoSuchObject()),
    ]
    assert utils.fit_var_binds(var_binds, 65000) == var_binds
