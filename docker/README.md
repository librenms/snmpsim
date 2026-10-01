# SNMP Simulator

The `Dockerfile` in the repository root builds two images from the snmpsim
sources in this repository:

* `ghcr.io/jellyfrog/snmpsim` – snmpsim, listening on UDP port `1161`.
* `ghcr.io/jellyfrog/snmpsim:<tag>-snmptrapd` – a PySNMP-based trap/inform
  receiver inspired by `snmpreceiver/snmptrapd.py`, listening on UDP port `1162`.
  It is published as `-snmptrapd` suffixed tags of the same image, and both
  share the same base layers.

Map the ports to the host ports you want (usually `161` and `162`).

Both images are based on distroless and run as the non-root user `nonroot`
(uid 65532). Mounted files must be readable by that user.

By default the snmpsim image contains an snmpwalk from `demo.snmplabs.com` under community name `demo`.

## Usage

To use your own snmpwalks you should mount a folder with snmpwalks like this:

    docker run -v /somewhere/with/snmpwalks:/usr/local/snmpsim/data \
               -p 161:1161/udp \
               ghcr.io/jellyfrog/snmpsim:master

The filename determines the SNMP community name.

Changes to existing snmpwalk files are picked up automatically. To pick up
added or removed files without a restart, send the container a `SIGHUP`:

    docker kill --signal=HUP <container>

You can also mount the whole `/usr/local/snmpsim` directory. snmpsim then reads
both `data/` and `variation/` from it.

To give snmpsim more flags, add them after the image name:

    docker run -p 161:1161/udp \
               ghcr.io/jellyfrog/snmpsim:master \
               --v3-user=testing --v3-auth-key=testing123

The image always adds `--agent-udpv4-endpoint=0.0.0.0:1161`. To replace it,
override the entrypoint with `--entrypoint /opt/venv/bin/snmpsim-command-responder`.

To run the lightweight SNMPv1/v2c responder instead, override the entrypoint
with `--entrypoint /opt/venv/bin/snmpsim-command-responder-lite` and pass
`--agent-udpv4-endpoint=0.0.0.0:1161` yourself.

### Read-only root filesystem

Both images support a read-only root filesystem. snmpsim writes its index cache
to `/tmp`, so mount a writable `/tmp`:

    docker run --read-only --tmpfs /tmp -p 161:1161/udp \
               ghcr.io/jellyfrog/snmpsim:master

The trap receiver writes nothing unless `SNMPTRAPD_LOG_FILE` is set.

In Kubernetes, set `readOnlyRootFilesystem: true` and mount an `emptyDir` at `/tmp`.

### Trap / Inform receiver

    docker run -p 162:1162/udp ghcr.io/jellyfrog/snmpsim:master-snmptrapd

The receiver respects these optional variables:

* `SNMPTRAPD_ADDRESS` / `SNMPTRAPD_PORT` – override the bind address/port (defaults `0.0.0.0:1162`).
* `SNMPTRAPD_COMMUNITY` – change the community string used for accepting traps (`public` by default).
* `SNMPTRAPD_LOG_FILE` – write trap logs to a file instead of stdout.
* `SNMPTRAPD_LOG_LEVEL` – change log verbosity (e.g. `DEBUG`, `INFO`, ...).
* `SNMPTRAPD_V3_USERS` – semicolon-separated list of SNMPv3 users in the form
  `user:authProto:authKey:privProto:privKey` (multiple users can be chained with `;`). Example:

  ```shell
  -e SNMPTRAPD_V3_USERS="tester:SHA:authpass1:AES128:privpass1;observer:MD5:authpass2:NONE:"
  ```

  Supported auth protocols: `MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, or `NONE`.
  Supported privacy protocols: `DES`, `3DES`, `AES128`, `AES192`, `AES256`, or `NONE`.
* `SNMPTRAPD_PYSNMP_DEBUG` – comma-separated PySNMP debug topics (e.g.
  `io,dsp,msgproc,secmod`). Valid values map to the flags in `pysnmp.debug.FLAG_MAP`.
  This enables low-level protocol traces that are very helpful when debugging SNMPv3
  auth/priv failures.

To learn more about snmpsim, please visit [its docs](https://www.pysnmp.com/snmpsim/).

## Building locally

From the repository root:

    docker build --target snmpsim -t local/snmpsim .
    docker build --target snmptrapd -t local/snmptrapd .

or use `docker/local-build.sh` and `docker/local-run.sh`.

## Bug Reports

Issues about this image should be reported to https://github.com/lextudio/pysnmp/issues.
