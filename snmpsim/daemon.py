#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import sys

from snmpsim import error

if sys.platform[:3] == "win":

    def daemonize(pidfile):
        raise error.SnmpsimError("Windows is not inhabited with daemons!")

    def notify_ready():
        pass

    def notify_failure(message):
        pass

    class PrivilegesOf:
        """Context manager performing nothing on Windows"""

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            pass

        def __exit__(self, *args):
            pass

else:
    import asyncio
    import os
    import pwd
    import grp
    import atexit
    import signal
    import tempfile

    # write end of the pipe the launching process waits on, until ready
    _status_fd = None

    def _notify(message):
        global _status_fd

        if _status_fd is None:
            return

        try:
            os.write(_status_fd, ("%s\n" % message.replace("\n", " ")).encode())

        except OSError:
            pass

        os.close(_status_fd)
        _status_fd = None

    def notify_ready():
        """Let the launching process exit, the daemon is serving now"""
        _notify("ready")

    def notify_failure(message):
        """Make the launching process fail with this message"""
        _notify(message)

    def _wait_ready(fd):
        """Exit the launching process once the daemon is ready or failed"""
        status = b""

        while not status.endswith(b"\n"):
            chunk = os.read(fd, 4096)

            if not chunk:
                break

            status += chunk

        status = status.decode(errors="replace").strip()

        if status == "ready":
            os._exit(0)

        sys.stderr.write(
            "ERROR: daemon failed to start: %s\r\n"
            % (status or "exited without reporting its status")
        )
        sys.stderr.flush()
        os._exit(1)

    def daemonize(pidfile):
        global _status_fd

        if pidfile:
            pidfile = os.path.abspath(pidfile)

        # forked children lose the current event loop (Python 3.12+), but
        # objects set up before daemonizing are bound to it
        try:
            loop = asyncio.get_event_loop()

        except RuntimeError:
            loop = None

        rfd, wfd = os.pipe()

        try:
            pid = os.fork()
            if pid > 0:
                # wait for the daemon, then exit first parent
                os.close(wfd)
                _wait_ready(rfd)

        except OSError as exc:
            raise error.SnmpsimError("ERROR: fork #1 failed: %s" % exc)

        os.close(rfd)
        _status_fd = wfd

        # relay errors raised before the daemon is ready
        excepthook = sys.excepthook

        def excepthook_cb(exc_type, exc, tb):
            notify_failure(str(exc) or exc_type.__name__)
            excepthook(exc_type, exc, tb)

        sys.excepthook = excepthook_cb

        # not ready yet, e.g. an error logged and an exit code returned
        atexit.register(_notify, "exited before it was ready, see the log for details")

        # decouple from parent environment, but keep the working directory
        # so relative paths given on the command line keep working
        try:
            os.setsid()

        except OSError:
            pass

        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                os._exit(0)

        except OSError as exc:
            raise error.SnmpsimError("ERROR: fork #2 failed: %s" % exc)

        if loop is not None:
            asyncio.set_event_loop(loop)

        def signal_cb(s, f):
            raise KeyboardInterrupt

        for s in signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT:
            signal.signal(s, signal_cb)

        # write pidfile
        def atexit_cb():
            try:
                if pidfile:
                    os.remove(pidfile)

            except OSError:
                pass

        atexit.register(atexit_cb)

        try:
            if pidfile:
                fd, nm = tempfile.mkstemp(dir=os.path.dirname(pidfile))
                os.write(fd, ("%d\n" % os.getpid()).encode("utf-8"))
                os.close(fd)
                os.rename(nm, pidfile)

        except Exception as exc:
            exc = error.SnmpsimError(f"Failed to create PID file {pidfile}: {exc}")
            notify_failure(str(exc))
            raise exc

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull)
        so = open(os.devnull, "a+")
        se = open(os.devnull, "a+")

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    class PrivilegesOf:
        """Context manager executing under reduced privileges"""

        def __init__(self, uname, gname, final=False):
            self._uname = uname
            self._gname = gname
            self._final = final
            self._olduid = self._oldgid = None

        def __enter__(self):
            if os.getenv("SNMPSIM_ALLOW_ROOT") == "true":
                return

            if os.getuid() != 0:
                if self._uname or self._gname:
                    try:
                        pw_name = pwd.getpwnam(self._uname).pw_name
                        gr_name = grp.getgrnam(self._gname).gr_name

                    except Exception as exc:
                        raise error.SnmpsimError(
                            "getpwnam()/getgrnam() failed for %s/%s: "
                            "%s" % (self._uname, self._gname, exc)
                        )

                    if self._uname != pw_name or self._gname != gr_name:
                        raise error.SnmpsimError(
                            "Process is running under different UID/GID"
                        )
                else:
                    return

            else:
                if not self._uname or not self._gname:
                    raise error.SnmpsimError(
                        "Must drop privileges to a non-privileged user&group"
                    )

            try:
                runningUid = pwd.getpwnam(self._uname).pw_uid
                runningGid = grp.getgrnam(self._gname).gr_gid

            except Exception as exc:
                raise error.SnmpsimError(
                    "getpwnam()/getgrnam() failed for %s/%s: "
                    "%s" % (self._uname, self._gname, exc)
                )

            try:
                os.setgroups([])

            except Exception as exc:
                raise error.SnmpsimError("setgroups() failed: %s" % exc)

            try:
                if self._final:
                    os.setgid(runningGid)
                    os.setuid(runningUid)

                else:
                    self._olduid = os.getuid()
                    self._oldgid = os.getgid()

                    os.setegid(runningGid)
                    os.seteuid(runningUid)

            except Exception as exc:
                raise error.SnmpsimError(
                    "%s failed for %s/%s: %s"
                    % (
                        self._final and "setgid()/setuid()" or "setegid()/seteuid()",
                        runningGid,
                        runningUid,
                        exc,
                    )
                )

            os.umask(63)  # 0077

        def __exit__(self, *args):
            if self._olduid is None or self._oldgid is None:
                return

            try:
                os.setegid(self._oldgid)
                os.seteuid(self._olduid)

            except Exception as exc:
                raise error.SnmpsimError(
                    "setegid()/seteuid() failed for %s/%s: %s"
                    % (self._oldgid, self._olduid, exc)
                )
