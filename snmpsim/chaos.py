#
# This file is part of snmpsim software.
#
# License: https://www.pysnmp.com/snmpsim/license.html
#
# Chaos mode: misbehave like the buggy SNMP agents found in the wild
#
# A share of the requests, given by the chaos rate, is answered with one
# of the enabled quirks that apply to the request: e.g. the quirks for
# missing OIDs only apply to GET requests for OIDs not in the data file.
# A kind of quirks is picked at random first, then a quirk of that kind,
# so the quirks for rare situations are not outnumbered by the others.
#
import asyncio
import collections
import random
import time

from pyasn1.type import univ
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905

from snmpsim import fastber
from snmpsim import log

BULK_LIMIT = 10
HANG_SECONDS = 3
MAX_OIDS = 5
DELAY_SECONDS = 1.5

# quirk name -> (situation, safe, description)
#
# Safe quirks are survived by net-snmp tools run with default flags, the
# others need per-device settings in the SNMP manager (e.g. walking with
# -Cc, disabling GETBULK, fewer max-repetitions or OIDs per request).
QUIRKS = {
    "get-as-next": (
        "missing",
        True,
        "GET of a missing OID answers with the next existing OID",
    ),
    "null-for-missing": (
        "missing",
        True,
        "GET of a missing OID answers with a NULL value",
    ),
    "drop-missing": (
        "missing",
        True,
        "GET response leaves out missing OIDs",
    ),
    "swap-exceptions": (
        "missing-or-end",
        True,
        "endOfMibView for missing OIDs, noSuchObject past the end of the MIB",
    ),
    "generr-for-missing": (
        "missing",
        False,
        "GET with a missing OID fails with genErr",
    ),
    "nosuchname-fails-pdu": (
        "missing",
        False,
        "SNMPv2c GET with a missing OID fails with noSuchName, as in SNMPv1",
    ),
    "jump-at-end": (
        "end",
        True,
        "past the end of the MIB, answer with an OID not in the data file",
    ),
    "end-as-nosuchname": (
        "end",
        True,
        "past the end of the MIB, fail with noSuchName instead of endOfMibView",
    ),
    "wrap-at-end": (
        "end",
        False,
        "past the end of the MIB, continue from the first OID",
    ),
    "repeat-at-end": (
        "end",
        False,
        "past the end of the MIB, repeat the last OID",
    ),
    "unordered": (
        "next",
        False,
        "neighbouring table rows are walked in swapped order, OIDs are not increasing",
    ),
    "bulk-short": (
        "bulk",
        True,
        "GETBULK ignores max-repetitions and answers one repetition",
    ),
    "bulk-overrun": (
        "bulk",
        True,
        "GETBULK answers twice the repetitions",
    ),
    "toobig": (
        "big-bulk",
        False,
        f"GETBULK asking for more than {BULK_LIMIT} var-binds fails with tooBig",
    ),
    "hang-after-bulk": (
        "big-bulk",
        False,
        f"agent stops answering for {HANG_SECONDS} seconds after a GETBULK "
        f"asking for more than {BULK_LIMIT} var-binds",
    ),
    "max-oid": (
        "many-oids",
        False,
        f"GET and GETNEXT with more than {MAX_OIDS} OIDs fail with tooBig",
    ),
    "wrong-type": (
        "value",
        True,
        "an integer value is sent with another integer type",
    ),
    "signed-unsigned": (
        "value",
        True,
        "a large unsigned value is encoded as a negative number",
    ),
    "trailing-nul": (
        "value",
        True,
        "a text value ends with a NUL byte",
    ),
    "non-utf8": (
        "value",
        True,
        "a text value ends with non UTF-8 (GBK) bytes",
    ),
    "drop-first": (
        "wire",
        True,
        "first transmission of the request is not answered",
    ),
    "duplicate": (
        "wire",
        True,
        "response is sent twice",
    ),
    "stale-response": (
        "wire",
        True,
        "response is preceded by one with another request ID",
    ),
    "long-lengths": (
        "wire",
        True,
        "BER lengths use the long form",
    ),
    "delay": (
        "wire",
        False,
        f"response is sent after {DELAY_SECONDS} seconds",
    ),
}

PRESETS = {
    "safe": [name for name, (_, safe, _) in QUIRKS.items() if safe],
    "all": list(QUIRKS),
}

DEFAULT_PRESET = "safe"

TOO_BIG = 1
NO_SUCH_NAME = 2
GEN_ERR = 5

# situation -> kind of quirks
_KINDS = {
    "missing": "exception",
    "end": "exception",
    "missing-or-end": "exception",
    "big-bulk": "bulk",
    "many-oids": "bulk",
}

_NULL = univ.Null("")

_END_OF_MIB = rfc1905.EndOfMibView.tagSet
_EXCEPTIONS = frozenset(
    (
        rfc1905.NoSuchObject.tagSet,
        rfc1905.NoSuchInstance.tagSet,
        rfc1905.EndOfMibView.tagSet,
    )
)

_WRONG_TYPES = {
    rfc1902.Counter32.tagSet: rfc1902.Gauge32,
    rfc1902.Gauge32.tagSet: rfc1902.Counter32,
    rfc1902.TimeTicks.tagSet: rfc1902.Gauge32,
}

# Counter32, Gauge32, TimeTicks, Counter64 -> BER tag
_UNSIGNED_TAGS = {
    rfc1902.Counter32.tagSet: 0x41,
    rfc1902.Gauge32.tagSet: 0x42,
    rfc1902.TimeTicks.tagSet: 0x43,
    rfc1902.Counter64.tagSet: 0x46,
}

# usmStatsUnsupportedSecLevels.0, net-snmp agents answer it past mib-2
_JUMP_OID = univ.ObjectIdentifier("1.3.6.1.6.3.15.1.1.1.0")

# a Huawei agent's entPhysicalDescr suffix, LibreNMS issue #20361
_NON_UTF8 = b" \xb7\xe7\xbb\xfa"

# constructed types in a response message: SEQUENCE, GetResponse PDU
_CONSTRUCTED = frozenset((0x30, fastber.GET_RESPONSE))

# remembered requests for drop-first
_MAX_SEEN = 4096


def parse_quirks(spec):
    """Turn "preset,quirk,-quirk,..." into the list of enabled quirks"""
    enabled = []

    for item in spec.split(","):
        item = item.strip()

        if not item:
            continue

        remove = item.startswith("-")
        name = item.lstrip("-+")

        if name in PRESETS:
            names = PRESETS[name]

        elif name in QUIRKS:
            names = [name]

        else:
            raise ValueError(
                'unknown chaos preset or quirk "%s", choose from: %s'
                % (name, ", ".join(list(PRESETS) + list(QUIRKS)))
            )

        for name in names:
            if remove:
                if name in enabled:
                    enabled.remove(name)

            elif name not in enabled:
                enabled.append(name)

    return enabled


def _is_exception(var_bind):
    # var-binds encoded from data file records are never exceptions
    return (
        type(var_bind) is not fastber.EncodedVarBind
        and var_bind[1].tagSet in _EXCEPTIONS
    )


def _is_end(var_bind):
    return (
        type(var_bind) is not fastber.EncodedVarBind
        and var_bind[1].tagSet == _END_OF_MIB
    )


def _is_text(octets):
    return all(0x20 <= x < 0x7F or x in (0x09, 0x0A, 0x0D) for x in octets)


def _mangle(quirk, var_bind):
    """Var-bind with a value quirk applied or None if it does not apply"""
    if _is_exception(var_bind):
        return

    oid, value = var_bind
    tag_set = value.tagSet

    if quirk == "wrong-type":
        if tag_set in _WRONG_TYPES:
            return oid, _WRONG_TYPES[tag_set](int(value))

        if tag_set == rfc1902.Integer32.tagSet and int(value) >= 0:
            return oid, rfc1902.Gauge32(int(value))

        if tag_set == rfc1902.Counter64.tagSet and int(value) < 2**32:
            return oid, rfc1902.Counter32(int(value))

    elif quirk == "signed-unsigned":
        tag = _UNSIGNED_TAGS.get(tag_set)
        number = int(value) if tag else 0

        # values with the top bit set need a leading zero octet, leave it out
        if number and number.bit_length() % 8 == 0:
            encoded = fastber._encode_tlv(
                0x30,
                fastber._encode_tlv(0x06, fastber._encode_oid(tuple(oid)))
                + fastber._encode_tlv(
                    tag, number.to_bytes(number.bit_length() // 8, "big")
                ),
            )

            return fastber.EncodedVarBind(
                str(oid), encoded, lambda var_bind=(oid, value): var_bind
            )

    elif tag_set == rfc1902.OctetString.tagSet:
        octets = value.asOctets()

        if _is_text(octets):
            suffix = b"\0" if quirk == "trailing-nul" else _NON_UTF8
            return oid, rfc1902.OctetString(octets + suffix)


def _parse_tlvs(data):
    items = []
    idx = 0

    while idx < len(data):
        tag, start, end = fastber._header(data, idx)
        value = data[start:end]

        if tag in _CONSTRUCTED:
            value = _parse_tlvs(value)

        items.append([tag, value])
        idx = end

    return items


def _build_tlvs(items, long_lengths=False):
    encoded = []

    for tag, value in items:
        if isinstance(value, list):
            value = _build_tlvs(value, long_lengths)

        if long_lengths:
            length = len(value)
            length = length.to_bytes(max(1, (length.bit_length() + 7) // 8), "big")
            encoded.append(bytes((tag, 0x80 | len(length))) + length + value)

        else:
            encoded.append(fastber._encode_tlv(tag, value))

    return b"".join(encoded)


class Chaos:
    """Make responses misbehave like buggy SNMP agents do"""

    def __init__(self, quirks, rate=0.1):
        self.quirks = list(quirks)
        self.rate = rate

        # wire quirk picked for the response being encoded
        self.wire_quirk = None

        self._hung_until = 0
        self._seen = collections.OrderedDict()

    def __str__(self):
        return "chaos mode, quirks %s, rate %s" % (",".join(self.quirks), self.rate)

    @staticmethod
    def _fired(community, name):
        if log.enabled(log.LOG_INFO):
            log.info(
                'Chaos quirk "%s" for community "%s"'
                % (name, community.decode("iso-8859-1"))
            )

    def hung(self, community):
        """Whether the agent does not answer at all at the moment"""
        if time.monotonic() < self._hung_until:
            self._fired(community, "hang-after-bulk")
            return True

        return False

    def apply(
        self,
        community,
        pdu_type,
        req_var_binds,
        non_repeaters,
        max_repetitions,
        var_binds,
        mib_instrum,
    ):
        """Maybe mangle a response.

        Returns an (error_status, error_index, var_binds) response.
        """
        self.wire_quirk = None

        if random.random() >= self.rate:
            return 0, 0, var_binds

        if pdu_type == fastber.GET_BULK_REQUEST:
            n = min(int(non_repeaters), len(req_var_binds))
            r = len(req_var_binds) - n
            size = n + r * int(max_repetitions)

        else:
            n = 0 if pdu_type == fastber.GET_REQUEST else len(req_var_binds)
            r = 0
            size = len(req_var_binds)

        situations = {"wire"}

        if pdu_type == fastber.GET_REQUEST:
            if any(_is_exception(var_bind) for var_bind in var_binds):
                situations.update(("missing", "missing-or-end"))

        else:
            situations.add("next")

            if any(_is_end(var_bind) for var_bind in var_binds):
                situations.update(("end", "missing-or-end"))

        if r:
            situations.add("bulk")

            if size > BULK_LIMIT:
                situations.add("big-bulk")

        elif size > MAX_OIDS:
            situations.add("many-oids")

        candidates = [name for name in self.quirks if QUIRKS[name][0] in situations]

        values = {}

        for name in self.quirks:
            if QUIRKS[name][0] == "value":
                values[name] = [
                    idx
                    for idx, var_bind in enumerate(var_binds)
                    if _mangle(name, var_bind) is not None
                ]

                if values[name]:
                    candidates.append(name)

        if not candidates:
            return 0, 0, var_binds

        kinds = collections.defaultdict(list)

        for name in candidates:
            situation = QUIRKS[name][0]
            kinds[_KINDS.get(situation, situation)].append(name)

        quirk = random.choice(random.choice(list(kinds.values())))
        situation = QUIRKS[quirk][0]

        self._fired(community, quirk)

        var_binds = list(var_binds)

        if situation == "wire":
            self.wire_quirk = quirk

        elif situation == "value":
            idx = random.choice(values[quirk])
            var_binds[idx] = _mangle(quirk, var_binds[idx])

        elif quirk in ("max-oid", "toobig"):
            return TOO_BIG, 0, []

        elif quirk == "hang-after-bulk":
            self._hung_until = time.monotonic() + HANG_SECONDS

        elif quirk == "unordered":
            var_binds = self._unordered(req_var_binds, n, r, var_binds, mib_instrum)

        elif situation == "bulk":
            var_binds = self._bulk(quirk, var_binds, n, r, mib_instrum)

        elif pdu_type == fastber.GET_REQUEST:
            return self._missing(quirk, req_var_binds, var_binds, mib_instrum)

        else:
            return self._end(quirk, req_var_binds, var_binds, n, r, mib_instrum)

        return 0, 0, var_binds

    @staticmethod
    def _missing(quirk, req_var_binds, var_binds, mib_instrum):
        missing = [
            idx for idx, var_bind in enumerate(var_binds) if _is_exception(var_bind)
        ]

        if quirk == "generr-for-missing":
            return GEN_ERR, missing[0] + 1, req_var_binds

        if quirk == "nosuchname-fails-pdu":
            return NO_SUCH_NAME, missing[0] + 1, req_var_binds

        if quirk == "drop-missing":
            return 0, 0, [vb for vb in var_binds if not _is_exception(vb)]

        for idx in missing:
            oid = var_binds[idx][0]

            if quirk == "get-as-next":
                (next_var_bind,) = mib_instrum.read_next_variables(req_var_binds[idx])

                if not _is_exception(next_var_bind):
                    var_binds[idx] = next_var_bind

            elif quirk == "null-for-missing":
                var_binds[idx] = oid, _NULL

            elif quirk == "swap-exceptions":
                var_binds[idx] = oid, rfc1905.endOfMibView

        return 0, 0, var_binds

    @staticmethod
    def _end(quirk, req_var_binds, var_binds, n, r, mib_instrum):
        # GETNEXT var-binds count as non-repeaters, GETBULK repeats r columns
        columns = n + r

        def previous(idx):
            return req_var_binds[idx] if idx < columns else var_binds[idx - r]

        ends = [idx for idx, var_bind in enumerate(var_binds) if _is_end(var_bind)]

        if quirk == "end-as-nosuchname":
            first = ends[0]

            if first < columns:
                # the end comes first, fail the request
                idx = first if first < n else n + (first - n) % r
                return NO_SUCH_NAME, idx + 1, req_var_binds

            # stop before the end, the next request fails
            return 0, 0, var_binds[: n + (first - n) // r * r]

        if quirk == "swap-exceptions":
            for idx in ends:
                var_binds[idx] = var_binds[idx][0], rfc1905.noSuchObject

        elif quirk == "jump-at-end":
            for idx in ends:
                if previous(idx)[0] < _JUMP_OID:
                    var_binds[idx] = _JUMP_OID, rfc1902.Counter32(0)

        elif quirk == "wrap-at-end":
            current = (univ.ObjectIdentifier((0, 0)), _NULL)

            for idx in ends:
                (current,) = mib_instrum.read_next_variables(current)

                if _is_exception(current):
                    break

                var_binds[idx] = current

        elif quirk == "repeat-at-end":
            for idx in ends:
                var_bind = previous(idx)

                if idx < columns:
                    (var_bind,) = mib_instrum.read_variables(var_bind)

                    if _is_exception(var_bind):
                        var_bind = var_bind[0], _NULL

                var_binds[idx] = var_bind

        return 0, 0, var_binds

    @staticmethod
    def _bulk(quirk, var_binds, n, r, mib_instrum):
        repetitions = (len(var_binds) - n) // r

        if quirk == "bulk-short":
            return var_binds[: n + r]

        # bulk-overrun
        last = var_binds[-r:]

        for _ in range(repetitions):
            if any(_is_exception(var_bind) for var_bind in last):
                break

            last = mib_instrum.read_next_variables(*last)
            var_binds.extend(last)

        return var_binds

    def _unordered(self, req_var_binds, n, r, var_binds, mib_instrum):
        """Redo GETNEXT and GETBULK in an agent order with swapped rows"""
        rsp_var_binds = [
            self._unordered_next(var_bind, mib_instrum)
            for var_bind in req_var_binds[:n]
        ]

        last = req_var_binds[n:]

        for _ in range((len(var_binds) - n) // r if r else 0):
            if all(_is_end(var_bind) for var_bind in last):
                break

            last = [self._unordered_next(var_bind, mib_instrum) for var_bind in last]
            rsp_var_binds.extend(last)

        return rsp_var_binds

    @staticmethod
    def _unordered_next(var_bind, mib_instrum):
        """GETNEXT in an agent order with neighbouring table rows swapped.

        Rows with an odd last sub-identifier swap places with the following
        row, if there is one: rows 1, 2, 3, 4, 5 are walked as 2, 1, 4, 3, 5.
        """

        def partner(oid):
            last = oid[-1]

            if last % 2:
                other = oid[:-1] + (last + 1,)

            elif last:
                other = oid[:-1] + (last - 1,)

            else:
                return

            (other,) = mib_instrum.read_variables((univ.ObjectIdentifier(other), _NULL))

            if not _is_exception(other):
                return other

        if _is_exception(var_bind):
            return var_bind

        oid = tuple(var_bind[0])

        if oid:
            (current,) = mib_instrum.read_variables((var_bind[0], _NULL))

            if not _is_exception(current):
                other = partner(oid)

                if other is not None:
                    if oid[-1] % 2 == 0:
                        # first of the pair, the odd row follows
                        return other

                    # second of the pair, continue after the even row
                    var_bind = other

        (next_var_bind,) = mib_instrum.read_next_variables(var_bind)

        if _is_exception(next_var_bind):
            return next_var_bind

        next_oid = tuple(next_var_bind[0])

        if next_oid[-1] % 2:
            other = partner(next_oid)

            if other is not None:
                return other

        return next_var_bind

    def wire(self, transport_address, request_id, packet):
        """Packets to send for a response as a list of (delay, packet)"""
        quirk = self.wire_quirk
        self.wire_quirk = None

        if quirk == "drop-first":
            seen = (transport_address, request_id)

            if seen not in self._seen:
                self._seen[seen] = True

                if len(self._seen) > _MAX_SEEN:
                    self._seen.popitem(last=False)

                return []

        elif quirk == "duplicate":
            return [(0, packet), (0, packet)]

        elif quirk == "stale-response":
            message = _parse_tlvs(packet)
            pdu = message[0][1][2][1]
            pdu[0][1] = fastber._encode_integer((request_id + 2**30) % 2**31)

            return [(0, _build_tlvs(message)), (0, packet)]

        elif quirk == "long-lengths":
            return [(0, _build_tlvs(_parse_tlvs(packet), long_lengths=True))]

        elif quirk == "delay":
            return [(DELAY_SECONDS, packet)]

        return [(0, packet)]


def send_packets(send, packets):
    """Send (delay, packet) pairs, the delayed ones from the event loop"""
    for delay, packet in packets:
        if delay:
            asyncio.get_running_loop().call_later(delay, send, packet)

        else:
            send(packet)
