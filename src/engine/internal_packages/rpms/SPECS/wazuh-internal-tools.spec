Name:           wazuh-internal-tools
Version:        0.1.0
Release:        1
Summary:        Wazuh Internal Engine Tools (runtime venv + offline wheels)
License:        GPL-2.0-only
URL:            https://wazuh.com
Source0:        %{name}-%{version}.tar.gz
BuildArch:      x86_64

# ------------------------------
# Debug subpackages disabled
# ------------------------------
%global debug_package %{nil}
%undefine _debugsource_packages
%global _enable_debug_packages 0

# ------------------------------
# Build dependencies
# ------------------------------
BuildRequires:  python3
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
BuildRequires:  bash
BuildRequires:  coreutils
BuildRequires:  findutils
BuildRequires:  sed
BuildRequires:  tar
BuildRequires:  gzip
BuildRequires:  rsync

# ------------------------------
# Runtime dependencies
# ------------------------------
Requires:       python3

# ------------------------------
# Installation paths
# ------------------------------
%global prefix  /opt/wazuh-internal-tools
%global venv    %{prefix}/venv
%global wheelsd %{prefix}/wheels

%description
Wazuh internal CLI utilities.  
The virtual environment is created during %%post using the system Python.  
All packages are installed offline from bundled wheels.  
CLI wrappers are installed under /usr/bin and execute `python -m <module>` inside the venv.

# =====================
# == PREPARE STAGE ====
# =====================
%prep
%autosetup -n %{name}-%{version}

# =====================
# == BUILD STAGE ======
# =====================
%build
/usr/bin/bash -euxo pipefail <<'BASH'
PY=python3
$PY -m pip install --upgrade pip wheel setuptools build

mkdir -p dist/wheels build/compat

# Helper to build PEP517 packages
build_pep517 () {  # $1=path
  $PY -m build --wheel "$1" --outdir dist/wheels
}

# Build legacy-compatible wheel when PEP517 fails
build_legacy_from_copy () {  # $1=src_path  $2=package_name  $3="mod1 mod2 ..."
  src="$1"
  pkg="$2"
  mods="$3"
  dst="build/compat/$(basename "$src")"
  rm -rf "$dst"
  rsync -a "$src/" "$dst/"

  if [ -f "$dst/pyproject.toml" ]; then
    mv "$dst/pyproject.toml" "$dst/pyproject.toml.disabled"
  fi

  if [ ! -f "$dst/setup.cfg" ] && [ ! -f "$dst/setup.py" ]; then
    cat >"$dst/setup.cfg" <<EOF
[metadata]
name = ${pkg}
version = 0.0.0
description = Temporary legacy build shim for ${pkg}

[options]
packages = find:
include_package_data = True
python_requires = >=3.8

[options.entry_points]
console_scripts =
$(for m in $mods; do echo "    ${m//_/-} = ${m}.__main__:main"; done)
EOF
    cat >"$dst/setup.py" <<'EOF'
from setuptools import setup
if __name__ == "__main__":
    setup()
EOF
  fi

  $PY -m pip wheel "$dst" \
    --wheel-dir dist/wheels \
    --no-deps \
    --no-build-isolation \
    --no-use-pep517
}

echo "[build] === Building internal wheels ==="
build_pep517 tools/api-communication

if ! build_pep517 tools/engine-suite; then
  echo "[build] PEP517 failed for engine-suite; falling back to legacy mode..."
  build_legacy_from_copy tools/engine-suite engine-suite \
    "engine_catalog engine_archiver engine_decoder engine_router engine_schema engine_policy engine_geo engine_test engine_test_utils helper_test health_test integration_test"
fi

build_pep517 test/engine-test-utils  || build_legacy_from_copy test/engine-test-utils  engine-test-utils   "engine_test_utils"
build_pep517 test/health_test/engine-health-test  || build_legacy_from_copy test/health_test/engine-health-test  engine-health-test  "health_test"
build_pep517 test/helper_tests/engine-helper-test || build_legacy_from_copy test/helper_tests/engine-helper-test engine-helper-test "helper_test"
build_pep517 test/integration_tests/engine-it     || build_legacy_from_copy test/integration_tests/engine-it     engine-it          "integration_test"

echo "[build] === Vendoring third-party dependencies (offline) ==="
REQS=$(mktemp)
cat > "$REQS" <<'EOF'
# httpx + stack
httpx==0.24.*
httpcore
h11
anyio
sniffio
certifi
idna
# requests + stack
requests==2.32.3
# charset-normalizer handled below (wheels-only fallback)
urllib3<3,>=1.26
# protobuf (abi3)
protobuf>=4.24,<6
# docker + deps
docker==7.*
graphviz
behave
websocket-client>=1.6,<2
packaging>=23
EOF

$PY -m pip download --only-binary=:all: --dest dist/wheels -r "$REQS"

# Ensure charset_normalizer universal wheel (py3-none-any), no sdist allowed
ensure_charset_normalizer_universal_no_sdist() {
  set -euo pipefail
  local WDIR="dist/wheels"
  if ls -1 "$WDIR"/charset_normalizer-*-py3-none-any.whl >/dev/null 2>&1; then
    echo "[build] charset_normalizer universal wheel already present."
    return 0
  fi

  echo "[build] charset_normalizer universal wheel missing. Trying fallback versions (wheels only)..."
  find "$WDIR" -maxdepth 1 -type f -name 'charset_normalizer-*.whl' ! -name '*-py3-none-any.whl' -delete || true

  local VERSIONS=("3.4.0" "3.3.2" "3.1.0" "2.1.1" "2.0.12")
  local v
  for v in "${VERSIONS[@]}"; do
    echo "[build] Trying charset_normalizer==$v (wheels only)..."
    if $PY -m pip download --only-binary=:all: --dest "$WDIR" "charset_normalizer==$v"; then
      if ls -1 "$WDIR"/charset_normalizer-"$v"-py3-none-any.whl >/dev/null 2>&1; then
        echo "[build] Found universal wheel for charset_normalizer==$v"
        find "$WDIR" -maxdepth 1 -type f -name 'charset_normalizer-*.whl' ! -name "charset_normalizer-$v-py3-none-any.whl" -delete || true
        return 0
      else
        echo "[build] Got non-universal wheel for $v; cleaning and trying next..."
        find "$WDIR" -maxdepth 1 -type f -name 'charset_normalizer-*.whl' ! -name '*-py3-none-any.whl' -delete || true
      fi
    fi
  done

  echo "[build][FATAL] Could not obtain a py3-none-any wheel for charset_normalizer." >&2
  ls -1 "$WDIR"/charset_normalizer-* 2>/dev/null || true
  exit 1
}
ensure_charset_normalizer_universal_no_sdist

# Download PyYAML/lxml manylinux builds for multiple Python ABIs
download_manylinux() {
  local spec="$1"
  for ver in 38 39 310 311 312; do
    $PY -m pip download "$spec" \
      --only-binary=:all: \
      --dest dist/wheels \
      --platform manylinux2014_x86_64 \
      --implementation cp \
      --python-version "$ver" \
      --abi "cp${ver}"
  done
}
download_manylinux "PyYAML==6.0.1"
download_manylinux "lxml==5.2.1"

echo "[build] Generated wheels:"
ls -1 dist/wheels
BASH

# =====================
# == INSTALL STAGE ====
# =====================
%install
rm -rf %{buildroot}

# 1) Copy wheels
install -d %{buildroot}%{wheelsd}
cp -a dist/wheels/* %{buildroot}%{wheelsd}/ 2>/dev/null || :

# 2) CLI wrappers under /usr/bin → run modules inside the venv
install -d %{buildroot}%{_bindir}

mk_wrapper () {
  local name="$1" mod="$2"
  cat > "%{buildroot}%{_bindir}/${name}" <<EOF
#!/bin/bash
exec /opt/wazuh-internal-tools/venv/bin/python -m ${mod} "\$@"
EOF
  chmod 0755 "%{buildroot}%{_bindir}/${name}"
}

mk_wrapper engine-catalog      engine_catalog
mk_wrapper engine-archiver     engine_archiver
mk_wrapper engine-decoder      engine_decoder
mk_wrapper engine-router       engine_router
mk_wrapper engine-schema       engine_schema
mk_wrapper engine-policy       engine_policy
mk_wrapper engine-geo          engine_geo
mk_wrapper engine-test         engine_test
mk_wrapper engine-test-utils   engine_test_utils
mk_wrapper engine-helper-test  helper_test
mk_wrapper engine-health-test  health_test
mk_wrapper engine-it           integration_test

# =====================
# == POST INSTALLATION
# =====================

%post -p /bin/bash
set -euo pipefail

VENV="%{venv}"
W="%{wheelsd}"
PY="$VENV/bin/python"

# Requires python3 on host
if ! command -v python3 >/dev/null 2>&1; then
  echo "[post] ERROR: python3 not found; wrappers will fail." >&2
  exit 0
fi

# Create venv if missing
if [ ! -x "$PY" ]; then
  python3 -m venv "$VENV"
fi

# Ensure pip inside venv
"$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
"$PY" -m pip install --upgrade pip wheel setuptools >/dev/null 2>&1 || true

# Offline selective installation by compatibility
if compgen -G "$W/*.whl" >/dev/null 2>&1; then
  echo "[post] Selecting compatible wheels for this interpreter..."

  CP_TAG="$("$PY" - <<'PY'
import sys
print(f"{sys.version_info[0]}{sys.version_info[1]}")
PY
)"

  # Internal wheels (installed with --no-deps)
  pick_internal() {
    shopt -s nullglob
    local files=()
    for f in "$W"/api_communication-*.whl \
             "$W"/engine_suite-*.whl \
             "$W"/engine_test_utils-*.whl \
             "$W"/engine_health_test-*.whl \
             "$W"/engine_helper_test-*.whl \
             "$W"/engine_it-*.whl; do
      [ -e "$f" ] && files+=("$f")
    done
    awk ' !seen[$0]++ ' < <(printf "%s\n" "${files[@]}")
  }

  # Third-party candidates compatible with the current interpreter
  pick_candidates() {
    shopt -s nullglob
    local files=()
    for f in "$W"/*-py3-none-any.whl; do files+=("$f"); done
    for f in "$W"/*-abi3-*.whl; do files+=("$f"); done
    for f in "$W"/*-cp${CP_TAG}-*.whl; do files+=("$f"); done
    awk ' !seen[$0]++ ' < <(printf "%s\n" "${files[@]}")
  }

  mapfile -t INTERNAL_WHEELS < <(pick_internal)
  mapfile -t CANDIDATES      < <(pick_candidates)

  # Exclude internal wheels from the third-party list
  pick_third_party() {
    if [ "${#INTERNAL_WHEELS[@]}" -gt 0 ]; then
      printf "%s\n" "${CANDIDATES[@]}" | grep -F -x -v -f <(printf "%s\n" "${INTERNAL_WHEELS[@]}") || true
    else
      printf "%s\n" "${CANDIDATES[@]}"
    fi
  }
  mapfile -t THIRD_PARTY_WHEELS < <(pick_third_party)

  # Sanity check: if requests is present, charset_normalizer universal must exist
  if printf "%s\n" "${THIRD_PARTY_WHEELS[@]}" | grep -q '/requests-'; then
    if ! printf "%s\n" "${THIRD_PARTY_WHEELS[@]}" | grep -q '/charset_normalizer-.*-py3-none-any\.whl$'; then
      echo "[post][ERROR] charset_normalizer py3-none-any wheel not found or not selected." >&2
      ls -1 "$W"/*.whl 2>/dev/null | sed 's/^/[post]   /' >&2
      exit 1
    fi
  fi

  # Internal installation (no dependencies)
  if [ "${#INTERNAL_WHEELS[@]}" -gt 0 ]; then
    echo "[post] Installing internal wheels (no-deps)..."
    printf '%s\n' "${INTERNAL_WHEELS[@]}" | sed 's/^/[post] internal: /'
    "$PY" -m pip install --no-index --find-links "$W" --no-deps "${INTERNAL_WHEELS[@]}"
  else
    echo "[post] WARNING: No internal wheels found."
  fi

  # Third-party installation
  if [ "${#THIRD_PARTY_WHEELS[@]}" -gt 0 ]; then
    echo "[post] Installing third-party wheels..."
    printf '%s\n' "${THIRD_PARTY_WHEELS[@]}" | sed 's/^/[post] third: /'
    "$PY" -m pip install --no-index --find-links "$W" "${THIRD_PARTY_WHEELS[@]}"
  else
    echo "[post] WARNING: No third-party wheels selected."
  fi

else
  echo "[post] WARNING: No wheels found at $W; skipping install." >&2
fi

# Summary
echo "[post] pip list (summary):"
"$PY" -m pip list | sed 's/^/[post] /'

# Create python3 alias inside venv
[ -x "$VENV/bin/python3" ] || ln -sf python "$VENV/bin/python3" 2>/dev/null || true

# Smoke test (non-fatal)
"$PY" - <<'PY' >/dev/null 2>&1 || echo "[post] WARNING: engine_catalog import failed."
import importlib; importlib.import_module("engine_catalog")
PY
exit 0

%preun -p /bin/bash
set -euo pipefail

if [ "${1:-0}" -eq 0 ]; then
  PREFIX="%{prefix}"

  # Safety guard
  case "$PREFIX" in
    /opt/wazuh-internal-tools|/opt/wazuh-internal-tools/*) ;;
    *) echo "[preun][FATAL] Refusing to remove outside expected PREFIX: $PREFIX" >&2; exit 1 ;;
  esac

  # Runtime artifacts
  rm -rf \
    "$PREFIX/venv" \
    "$PREFIX/.pip-selfcheck.json" \
    "$PREFIX/installed-freeze.txt" 2>/dev/null || true

  find "$PREFIX" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
  find "$PREFIX" -type f -name '*.py[co]' -delete 2>/dev/null || true
  rmdir "$PREFIX" 2>/dev/null || true
fi

exit 0

%postun -p /bin/bash
set -euo pipefail

if [ "${1:-0}" -eq 0 ]; then
  PREFIX="%{prefix}"
  [ -d "$PREFIX/venv" ] && rm -rf "$PREFIX/venv" || true
  [ -f "$PREFIX/.pip-selfcheck.json" ] && rm -f "$PREFIX/.pip-selfcheck.json" || true
  [ -f "$PREFIX/installed-freeze.txt" ] && rm -f "$PREFIX/installed-freeze.txt" || true
  rmdir "$PREFIX" 2>/dev/null || true
fi

exit 0

# =====================
# == FILES ============
# =====================
%files
%{_bindir}/engine-catalog
%{_bindir}/engine-archiver
%{_bindir}/engine-decoder
%{_bindir}/engine-router
%{_bindir}/engine-schema
%{_bindir}/engine-policy
%{_bindir}/engine-geo
%{_bindir}/engine-test
%{_bindir}/engine-test-utils
%{_bindir}/engine-helper-test
%{_bindir}/engine-health-test
%{_bindir}/engine-it
%dir %{prefix}
%dir %{wheelsd}
%{wheelsd}/*
%ghost %dir %{venv}
%ghost %{prefix}/installed-freeze.txt
%ghost %{prefix}/.pip-selfcheck.json

%changelog
* Thu Oct 16 2025 Wazuh Team <dev@wazuh.com> - 0.1.0-1
- Implemented version fallback for charset_normalizer (wheels-only) including 2.1.1/2.0.12 to ensure py3-none-any availability.
- Vendored docker, websocket-client, and packaging.
- Two-phase installation: internal (no-deps) + filtered third-party wheels.
