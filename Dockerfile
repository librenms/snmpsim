# syntax=docker/dockerfile:1

# ---- Build stages: install snmpsim and its locked deps into a virtualenv ----
# Debian's own python3 is the same interpreter, at the same path
# (/usr/bin/python3), as in the distroless runtime, so the venv works there.
FROM debian:trixie-slim AS builder-base

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
 && apt-get update \
 && apt-get install -y --no-install-recommends python3

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv

ENV UV_PYTHON=/usr/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /src

# snmpsim with SNMPv3 privacy (cryptography) and MIB compilation (pysmi)
FROM builder-base AS builder

# Dependencies first, so this layer is reused until uv.lock changes
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev --extra full

COPY . .

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --no-dev --extra full

# snmpsim searches <sys.prefix>/snmpsim/{data,variation} (snmpsim/confdir.py).
# sys.prefix is now the venv, so link it to /usr/local/snmpsim, the documented
# mount path.
RUN ln -s /usr/local/snmpsim /opt/venv/snmpsim

# snmpsim without extras, enough for the SNMPv1/v2c-only lite responder
FROM builder-base AS builder-lite

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY . .

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --no-dev

RUN ln -s /usr/local/snmpsim /opt/venv/snmpsim

# ---- runtime: shared runtime (distroless, no shell, runs as uid 65532) ----
FROM gcr.io/distroless/python3-debian13:nonroot AS runtime

LABEL maintainer="support@lextudio.com"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ---- base: runtime with the full virtualenv ----
FROM runtime AS base

COPY --from=builder /opt/venv /opt/venv

# ---- snmptrapd: trap/inform receiver ----
FROM base AS snmptrapd

LABEL description="PySNMP trap/inform receiver from snmpsim"

COPY docker/snmptrapd.py /opt/snmptrapd.py

EXPOSE 1162/udp

ENTRYPOINT ["/opt/venv/bin/python", "/opt/snmptrapd.py"]

# ---- snmpsim-lite: the lightweight SNMPv1/v2c simulator ----
FROM runtime AS snmpsim-lite

COPY --from=builder-lite /opt/venv /opt/venv

LABEL description="Docker image for running the lightweight snmpsim SNMPv1/v2c responder"

COPY docker/data /usr/local/snmpsim/data

EXPOSE 1161/udp

# As PID 1 an unhandled SIGTERM is ignored, see the snmpsim stage below.
STOPSIGNAL SIGINT

# Worker processes default to SNMPSIM_WORKERS, a number or "auto".
ENTRYPOINT ["/opt/venv/bin/snmpsim-command-responder-lite", "--agent-udpv4-endpoint=0.0.0.0:1161"]

# ---- snmpsim: the simulator (last, so it is the default build target) ----
FROM base AS snmpsim

LABEL description="Docker image for running snmpsim (PySNMP Simulator)"

COPY docker/data /usr/local/snmpsim/data

EXPOSE 1161/udp

# snmpsim only handles SIGTERM when daemonized, and as PID 1 an unhandled
# SIGTERM is ignored. Python turns SIGINT into KeyboardInterrupt, which
# snmpsim handles.
STOPSIGNAL SIGINT

# Extra snmpsim flags can be given as container arguments.
ENTRYPOINT ["/opt/venv/bin/snmpsim-command-responder", "--agent-udpv4-endpoint=0.0.0.0:1161"]
