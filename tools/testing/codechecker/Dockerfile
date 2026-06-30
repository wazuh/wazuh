# CodeChecker combined analyzer + server image
#
# Single image that bundles:
#   - clang-20 / clang-tidy-20 / cppcheck  (SAST analyzers)
#   - CodeChecker CLI + web server          (pip install codechecker)
#   - Meta Infer / RacerD                   (static race detection)
#   - ThreadSanitizer runtime               (dynamic race detection)
#   - All scan scripts at /cc/
#
# CI usage (GitHub Actions):
#   docker run --rm -v /results:/results -e SCAN_REF=... -e TARGET_REF=... \
#     ghcr.io/wazuh/codechecker:latest bash /cc/run_ci.sh
#
# Local dev (docker compose, separate server + analyzer):
#   See tools/testing/codechecker/README.md
FROM public.ecr.aws/ubuntu/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive container=docker

# ---------------------------------------------------------------------------
# Version pins
# ---------------------------------------------------------------------------
ARG CODECHECKER_VERSION=6.27.3
ARG CLANG_MAJOR=20
ARG INFER_VERSION=1.2.0

# Add the LLVM APT repository (clang-20 not in Ubuntu 24.04 main).
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates gnupg wget && \
    wget -qO /usr/share/keyrings/llvm-snapshot.gpg.asc https://apt.llvm.org/llvm-snapshot.gpg.key && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg.asc] http://apt.llvm.org/noble/ llvm-toolchain-noble-${CLANG_MAJOR} main" \
        > /etc/apt/sources.list.d/llvm-${CLANG_MAJOR}.list && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Build toolchain + LLVM/clang + cppcheck + CodeChecker runtime deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang-${CLANG_MAJOR} \
        clang-tidy-${CLANG_MAJOR} \
        clang-tools-${CLANG_MAJOR} \
        llvm-${CLANG_MAJOR} \
        cppcheck \
        build-essential cmake make git curl wget \
        ca-certificates gnupg \
        python3 python3-pip python3-venv python3-dev \
        libsqlite3-dev libssl-dev zlib1g-dev \
        procps file unzip xz-utils \
        libtsan0 \
        socat netcat-openbsd \
        nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Register versioned clang tools as the unversioned defaults.
RUN update-alternatives --install /usr/bin/clang        clang        /usr/bin/clang-${CLANG_MAJOR}        100 && \
    update-alternatives --install /usr/bin/clang++      clang++      /usr/bin/clang++-${CLANG_MAJOR}      100 && \
    update-alternatives --install /usr/bin/clang-tidy   clang-tidy   /usr/bin/clang-tidy-${CLANG_MAJOR}   100 && \
    update-alternatives --install /usr/bin/clang-apply-replacements clang-apply-replacements /usr/bin/clang-apply-replacements-${CLANG_MAJOR} 100 && \
    update-alternatives --install /usr/bin/clang-extdef-mapping clang-extdef-mapping /usr/bin/clang-extdef-mapping-${CLANG_MAJOR} 100 && \
    ln -sf /usr/bin/scan-build-${CLANG_MAJOR} /usr/bin/scan-build 2>/dev/null || true

# CodeChecker CLI + web server from PyPI (includes `CodeChecker server`).
# Flawfinder: lightweight C/C++ security scanner for CWE-362 (TOCTOU), CWE-119, etc.
# flawfinder_to_plist.py (baked at /cc/) converts its --csv output to CodeChecker plist
# format, since report-converter -t flawfinder does not exist in CodeChecker 6.27.3.
RUN pip3 install --no-cache-dir --break-system-packages \
        "codechecker==${CODECHECKER_VERSION}" \
        flawfinder

# Meta Infer (RacerD static race detection).
# SHA-256 pinned to v1.2.0 x86_64 tarball — update when bumping INFER_VERSION.
ARG INFER_SHA256=21504063fb3a1dbc7919f34dc6e50ca0d35f50b996d91deb7b8bea8243d52d82
RUN curl -fsSL "https://github.com/facebook/infer/releases/download/v${INFER_VERSION}/infer-linux-x86_64-v${INFER_VERSION}.tar.xz" -o /tmp/infer.tar.xz && \
    echo "${INFER_SHA256}  /tmp/infer.tar.xz" | sha256sum -c - && \
    mkdir -p /opt/infer && \
    tar -xJf /tmp/infer.tar.xz -C /opt/infer --strip-components=1 && \
    ln -sf /opt/infer/bin/infer /usr/local/bin/infer && \
    rm -f /tmp/infer.tar.xz && \
    infer --version

# Sanity check (fails build if any tool is missing).
RUN clang --version && \
    clang-tidy --version && \
    cppcheck --version && \
    infer --version && \
    flawfinder --version && \
    report-converter --help >/dev/null && \
    CodeChecker version

# Bake scan scripts into the image at /cc/.
COPY . /cc/
RUN chmod +x /cc/*.sh 2>/dev/null || true

EXPOSE 8001
WORKDIR /workspace

# Default: sleep so `docker compose exec` can drive scripts interactively.
# CI overrides this with `bash /cc/run_ci.sh`.
CMD ["sleep", "infinity"]
