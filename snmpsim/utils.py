#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import asyncio
import importlib
import math
import os
import sys
import threading

import pysnmp
import pyasn1

try:
    import pysmi

except ImportError:  # optional, only needed for MIB compilation
    pysmi = None

import snmpsim

TITLE = """\
SNMP Simulator version {}, written by Ilya Etingof <etingof@gmail.com>
Using foundation libraries: pysmi {}, pysnmp {}, pyasn1 {}.
Python interpreter: {}
Documentation and support at https://www.pysnmp.com/snmpsim
""".format(
    snmpsim.__version__,
    pysmi.__version__ if pysmi else "n/a",
    pysnmp.__version__,
    pyasn1.__version__,
    sys.version,
)


def _cgroup_cpu_limit(root="/sys/fs/cgroup"):
    """CPU quota of this process's cgroup as a number of CPUs or None"""
    limits = []

    # cgroup v2: "<quota> <period>" or "max <period>" in cpu.max of the
    # process's cgroup and of its ancestors
    try:
        with open("/proc/self/cgroup") as f:
            path = next(
                (line[3:].strip() for line in f if line.startswith("0::")), None
            )

    except OSError:
        path = None

    if path is not None:
        path = path.strip("/")

        while True:
            try:
                with open(os.path.join(root, path, "cpu.max")) as f:
                    quota, period = f.read().split()

                if quota != "max":
                    limits.append(int(quota) / int(period))

            except (OSError, ValueError):
                pass

            if not path:
                break

            path = os.path.dirname(path)

    # cgroup v1, as mounted inside a container
    try:
        with open(os.path.join(root, "cpu", "cpu.cfs_quota_us")) as f:
            quota = int(f.read())

        with open(os.path.join(root, "cpu", "cpu.cfs_period_us")) as f:
            period = int(f.read())

        if quota > 0 and period > 0:
            limits.append(quota / period)

    except (OSError, ValueError):
        pass

    return min(limits) if limits else None


def available_cpus():
    """Number of CPUs this process can use, honouring container CPU limits"""
    try:
        cpus = len(os.sched_getaffinity(0))

    except AttributeError:  # not available on all platforms
        cpus = os.cpu_count() or 1

    limit = _cgroup_cpu_limit()

    if limit is not None:
        cpus = min(cpus, max(1, math.ceil(limit)))

    return cpus


def try_load(module, package=None):
    """Try to load given module, return `None` on failure"""
    try:
        return importlib.import_module(module, package)

    except ImportError:
        return


def split(val, sep):
    """Split a string into a list based on a separator"""
    for x in (3, 2, 1):
        if val.find(sep * x) != -1:
            return val.split(sep * x)

    return [val]


def run_in_new_loop(coroutine):
    """Run a coroutine in a new event loop and return its result"""
    result = None

    def run():
        nonlocal result
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            result = new_loop.run_until_complete(coroutine)
        finally:
            new_loop.close()

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()

    return result
