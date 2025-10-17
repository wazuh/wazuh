#!/usr/bin/env bash
set -euo pipefail

# -------- Args & env (compatible with generate.sh) ----------------------------
REVISION="${1:-}"          # Used for RPM Release override; informational in DEB
JOBS="${2:-}"              # Reserved for parallelism (if needed by your rules/spec)
CHECKSUM_ARG="${3:-no}"    # "yes" to emit .sha512 files; default "no"

SYSTEM="${SYSTEM:-deb}"                       # deb|rpm
SRC_ROOT="${SRC_ROOT:-/wazuh-local-src}"      # mounted repo path
OUTDIR="${OUTDIR:-/var/local/wazuh}"          # artifacts path (bind-mounted)
ARCH_INPUT="${ARCHITECTURE_TARGET:-amd64}"    # amd64|arm64|x86_64|aarch64

# Normalize arch names for DEB (amd64|arm64) and RPM (x86_64|aarch64)
norm_arch_deb() {
  case "${1}" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)             echo "amd64" ;;
  esac
}
norm_arch_rpm() {
  case "${1}" in
    x86_64|amd64)  echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *)             echo "x86_64" ;;
  esac
}

ARCH_DEB="$(norm_arch_deb "${ARCH_INPUT}")"
ARCH_RPM="$(norm_arch_rpm "${ARCH_INPUT}")"

# Working directories
WORK="/tmp/pkgbuild/wazuh-internal-tools"
rm -rf "${WORK}"
mkdir -p "${WORK}"
mkdir -p "${OUTDIR}"

echo "[i] SYSTEM: ${SYSTEM}"
echo "[i] SRC_ROOT: ${SRC_ROOT}"
echo "[i] WORK: ${WORK}"
echo "[i] OUTDIR: ${OUTDIR}"
echo "[i] ARCH_DEB: ${ARCH_DEB} | ARCH_RPM: ${ARCH_RPM}"

# Copy the entire repo so expected paths exist for both flows
cp -a "${SRC_ROOT}/." "${WORK}/"

# -------- Helpers -------------------------------------------------------------
sha_opt() {
  if [ "${CHECKSUM_ARG}" = "yes" ]; then
    local f="$1"
    sha512sum "${f}" > "${f}.sha512"
  fi
}

first_file_or_fail() {
  local pattern="$1"
  local file
  file="$(ls -1 ${pattern} 2>/dev/null | head -n1 || true)"
  [ -n "${file}" ] || { echo "[!] No file matched pattern: ${pattern}"; exit 1; }
  echo "${file}"
}

# Standardize output filename => name_version_arch.sys using real package metadata
stage_pkg() {
  local ext="$1" pkg="$2" name ver arch outname
  if [[ "$ext" == "deb" ]]; then
    name="$(dpkg-deb -f "$pkg" Package)"
    ver="$(dpkg-deb -f "$pkg" Version)"
    arch="$(dpkg-deb -f "$pkg" Architecture)"
    arch="$(norm_arch_deb "$arch")"
    name="${name//_/-}"
    outname="${name}_${ver}_${arch}.deb"
  else
    if ! command -v rpm >/dev/null 2>&1; then
      sudo apt-get update -y
      sudo apt-get install -y rpm
    fi
    read -r name ver arch < <(rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' "$pkg")
    arch="$(norm_arch_rpm "$arch")"
    name="${name//_/-}"
    outname="${name}_${ver}_${arch}.rpm"
  fi

  if [[ "$ext" == "rpm" ]]; then
    rm -f "${OUTDIR}/"*".${arch}.rpm" 2>/dev/null || true
  else
    rm -f "${OUTDIR}/"*.${arch}.deb 2>/dev/null || true
  fi

  echo "[i] Staging $(basename "$pkg") → ${OUTDIR}/${outname}"
  cp -f "$pkg" "${OUTDIR}/${outname}"
  sha_opt "${OUTDIR}/${outname}"
}

# ===================== DEB flow ==============================================
build_deb() {
  local SPECS_DIR="${SPECS_DIR:-${WORK}/internal_packages/debs/SPECS}"
  echo "[i] SPECS_DIR (DEB): ${SPECS_DIR}"

  mkdir -p "${WORK}/debian"
  cp -a "${SPECS_DIR}/." "${WORK}/debian/"

  chmod +x "${WORK}/debian/rules" || true
  chmod +x "${WORK}/debian/build_venv.sh" || true
  if [ -d "${WORK}/debian/wrappers" ]; then
    chmod +x "${WORK}/debian/wrappers/"* || true
  fi

  pushd "${WORK}" >/dev/null
  echo "[i] Running dpkg-buildpackage..."
  dpkg-buildpackage -us -uc -b -a "${ARCH_DEB}"
  popd >/dev/null

  shopt -s nullglob
  for f in "${WORK}/../"*.deb; do
    stage_pkg "deb" "$f"
  done
  echo "[i] DEB build completed."
}

# ===================== RPM flow ==============================================
build_rpm() {
  echo "[i] >>> RPM MODE"
  local RPMBUILD_TOP="${WORK}/rpmbuild"
  local SPECS_DIR_DEFAULT="${WORK}/internal_packages/rpms/SPECS"
  local SPECS_DIR="${SPECS_DIR:-${SPECS_DIR_DEFAULT}}"

  mkdir -p "${RPMBUILD_TOP}"/{SPECS,SOURCES,BUILD,RPMS,SRPMS}

  local spec
  spec="$(first_file_or_fail "${SPECS_DIR}/*.spec")"
  cp -f "${spec}" "${RPMBUILD_TOP}/SPECS/"
  spec="${RPMBUILD_TOP}/SPECS/$(basename "${spec}")"
  echo "[i] Using SPEC: ${spec}"

  local NAME VERSION
  NAME="$(awk -F: '/^[[:space:]]*Name[[:space:]]*:/ {sub(/^[ \t]+/,"",$2); sub(/[ \t]+$/,"",$2); print $2; exit}' "${spec}")"
  VERSION="$(awk -F: '/^[[:space:]]*Version[[:space:]]*:/ {sub(/^[ \t]+/,"",$2); sub(/[ \t]+$/,"",$2); print $2; exit}' "${spec}")"

  [ -n "${NAME}" ]    || { echo "[!] Could not extract Name from spec."; exit 1; }
  [ -n "${VERSION}" ] || { echo "[!] Could not extract Version from spec."; exit 1; }

  local RELEASE_DEF=()
  if [ -n "${REVISION:-}" ]; then
    RELEASE_DEF=( --define "release ${REVISION}" )
  fi

  local TARBALL="${NAME}-${VERSION}.tar.gz"
  echo "[i] Packing sources → ${TARBALL}"

  tar -C "${WORK}" \
    --exclude-vcs \
    --exclude="rpmbuild" \
    --exclude="_stage" \
    --exclude="output" \
    --exclude="*.pyc" \
    --exclude="__pycache__" \
    --exclude="*.egg-info" \
    --exclude="build" \
    --exclude="dist" \
    --exclude=".venv" --exclude="venv" \
    --exclude="node_modules" \
    --transform "s,^,${NAME}-${VERSION}/," \
    -czf "${RPMBUILD_TOP}/SOURCES/${TARBALL}" .

  local TARGET_OPT=( --target "${ARCH_RPM}" )

  echo "[i] Running rpmbuild..."
  rpmbuild -bb \
    "${spec}" \
    "${TARGET_OPT[@]}" \
    --define "_topdir ${RPMBUILD_TOP}" \
    --define "_sourcedir ${RPMBUILD_TOP}/SOURCES" \
    --define "_rpmdir ${RPMBUILD_TOP}/RPMS" \
    --define "_srcrpmdir ${RPMBUILD_TOP}/SRPMS" \
    "${RELEASE_DEF[@]}"

  shopt -s nullglob
  for f in "${RPMBUILD_TOP}/RPMS/${ARCH_RPM}/"*.rpm; do
    stage_pkg "rpm" "$f"
  done

  for f in "${RPMBUILD_TOP}/SRPMS/"*.src.rpm; do
    echo "[i] Copying SRPM $(basename "$f") → ${OUTDIR}"
    cp -f "$f" "${OUTDIR}/"
    sha_opt "${OUTDIR}/$(basename "$f")"
  done
  echo "[i] RPM build completed."
}

# ===================== Dispatcher ============================================
case "${SYSTEM}" in
  deb) build_deb ;;
  rpm) build_rpm ;;
  *)   echo "[!] SYSTEM must be 'deb' or 'rpm'"; exit 1 ;;
esac

echo "[i] Final artifacts in ${OUTDIR}:"
echo "[i] Done."
