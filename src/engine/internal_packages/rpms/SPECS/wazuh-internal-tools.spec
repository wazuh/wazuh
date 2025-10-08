Name:           wazuh-internal-tools
Version:        0.1.0
Release:        1
Summary:        Wazuh Internal Engine Tools (venv-based)
License:        BSD-3-Clause
URL:            https://wazuh.com
Source0:        %{name}-%{version}.tar.gz
BuildArch:      x86_64

# Disable debug subpackages/sources for a venv-centric payload
%global debug_package %{nil}
%undefine _debugsource_packages
%global _enable_debug_packages 0

# Build-time tools (adjust if your builder already provides them)
BuildRequires:  python38
BuildRequires:  python38-pip
BuildRequires:  python38-setuptools
BuildRequires:  python38-wheel
BuildRequires:  findutils
BuildRequires:  coreutils
BuildRequires:  sed

# Runtime: make sure a Python 3.8+ interpreter is available
Requires:       python38 >= 3.8

# Install locations
%global prefix  /opt/wazuh-internal-tools
%global venv    %{prefix}/venv

%description
Wazuh’s internal CLI tools installed in a dedicated Python virtual environment
at %{venv}. Command-line entry points are exposed via symlinks in /usr/bin.

%prep
%autosetup -n %{name}-%{version}

%build
# Enter the unpacked tree and build the venv just like in the Debian flow
cd %{_builddir}/%{buildsubdir}

# Build venv and install local components in a fixed order
/usr/bin/bash -euxo pipefail <<'BASH'
BASE="$PWD"
VENV_DIR="build/venv"

rm -rf "$VENV_DIR"
python3.8 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

python -V
pip -V
python -m pip install --upgrade pip wheel setuptools

EDITABLE="${EDITABLE:-0}"  # 1 for local dev, 0 when packaging

install_local () {
  local path="$1"; local label="$2"; local flags="${3:---no-deps --no-build-isolation}"
  if [ -f "$path/pyproject.toml" ] || [ -f "$path/setup.py" ]; then
    echo "[i] Installing $label from $path ($flags) editable=$EDITABLE"
    if [ "$EDITABLE" = "1" ]; then
      python -m pip install -e "$path" $flags
    else
      python -m pip install "$path" $flags
    fi
  else
    echo "[!] $label has no pyproject/setup at $path — skipping"
  fi
}

# --- Installation order (paths are relative to the unpacked tree) ---
install_local "$BASE//tools/api-communication"               "api-communication"   "--no-build-isolation"
install_local "$BASE//tools/engine-suite"                    "engine-suite"
install_local "$BASE//test/engine-test-utils"                "engine-test-utils"
install_local "$BASE//test/health_test/engine-health-test"   "health_test"
install_local "$BASE//test/helper_tests/engine-helper-test"  "helper_tests"
install_local "$BASE//test/integration_tests/engine-it"      "integration_tests"

# Optional smoke check
build/venv/bin/python - <<'PY'
import importlib, sys
importlib.import_module("engine_catalog")
print("[i] import engine_catalog OK")
PY
BASH

%install
rm -rf %{buildroot}

echo "[i] Copying venv into the install tree..."
install -d %{buildroot}%{prefix}
cp -a build/venv %{buildroot}%{venv}

echo "[i] Rewriting console_script shebangs to final path..."
/usr/bin/bash -ec '\
  PY="%{venv}/bin/python"; \
  for f in "%{buildroot}%{venv}"/bin/*; do \
    [ -f "$f" ] || continue; \
    if head -c 2 "$f" | grep -q "^#\!"; then \
      if head -n1 "$f" | grep -qi python; then \
        sed -i "1 s|^#!.*|#!${PY}|" "$f"; \
      fi; \
    fi; \
    chmod a+rx "$f"; \
  done'

echo "[i] Creating /usr/bin symlinks (Debian .links-style)..."
install -d %{buildroot}%{_bindir}
for cmd in engine-catalog engine-archiver engine-decoder engine-geo engine-policy \
           engine-router engine-schema engine-test engine-it engine-helper-test engine-health-test; do
  ln -sf %{venv}/bin/${cmd} %{buildroot}%{_bindir}/${cmd}
done

echo "[i] Minor cleanup..."
find %{buildroot}%{venv} -type d -name '__pycache__' -exec rm -rf {} +
find %{buildroot}%{venv} -type f -name '*.py[co]' -delete

%post
#!/bin/sh
# Post-install: align site-packages if pythonX.Y directory naming differs
set -eu
PREFIX="%{prefix}"
VENV="$PREFIX/venv"
BIN="$VENV/bin"
PY="$BIN/python"

fix_site_packages_alignment() {
  if [ ! -x "$PY" ]; then
    echo "[post] WARNING: $PY not found; skipping fix."
    return 0
  fi
  ver="$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')" || return 0
  want="$VENV/lib/python$ver"
  [ -d "$want" ] && return 0

  found="$(ls -1d "$VENV"/lib/python3.* 2>/dev/null | head -n1 || true)"
  if [ -n "$found" ] && [ -d "$found" ]; then
    echo "[post] Adjusting site-packages: $(basename "$found") -> python$ver"
    mv "$found" "$want" || true
  fi

  if [ ! -d "$want" ] || ! "$PY" -c "import sys; print(any('site-packages' in p for p in sys.path))" >/dev/null 2>&1; then
    old="$(ls -1d "$VENV"/lib/python3.* 2>/dev/null | head -n1 || true)"
    if [ -n "$old" ] && [ -d "$old/site-packages" ]; then
      sp="$old/site-packages"
      echo "[post] Injecting $sp into sys.path via sitecustomize.py"
      mkdir -p "$want/site-packages" || true
      cat >"$want/site-packages/sitecustomize.py" <<EOF
import sys
p = r"$sp"
if p not in sys.path:
    sys.path.insert(0, p)
EOF
      chmod 0644 "$want/site-packages/sitecustomize.py" || true
    fi
  fi

  # Ensure python3 entry exists (some scripts invoke it)
  [ -x "$BIN/python3" ] || ln -sf python "$BIN/python3" 2>/dev/null || true
}

fix_site_packages_alignment || true

# Optional smoke check (non-fatal)
if [ -x "$PY" ]; then
  "$PY" - <<'PY' >/dev/null 2>&1 || echo "[post] WARNING: engine_catalog import failed (check venv)."
import importlib; importlib.import_module("engine_catalog")
PY
fi
exit 0

%files
%{_bindir}/engine-archiver
%{_bindir}/engine-catalog
%{_bindir}/engine-decoder
%{_bindir}/engine-geo
%{_bindir}/engine-policy
%{_bindir}/engine-router
%{_bindir}/engine-schema
%{_bindir}/engine-test
%{_bindir}/engine-it
%{_bindir}/engine-helper-test
%{_bindir}/engine-health-test
%{prefix}/

%changelog
* Mon Oct 06 2025 Wazuh Team <dev@wazuh.com> - 0.1.0-1
- First RPM build without embedded runtime: copy venv, rewrite shebangs, and add /usr/bin symlinks
