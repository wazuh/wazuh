#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/llvm/llvm-project.git"
REF=""
WORKDIR="/tmp/llvm-clang-format-work"
BUILD_TYPE="Release"
JOBS="$(nproc)"
INSTALL_DIR="/usr/bin"
CLEAN=0
CMAKE_EXTRA_ARGS=()

usage() {
  cat <<EOF
Usage:
  $0 <branch-or-tag> [options]

Examples:
  $0 llvmorg-22.1.4
  $0 release/22.1.4 --install-dir "\$HOME/.local/bin"
  $0 main --jobs 8 --clean

Options:
  --repo URL             llvm-project repository URL. Default: ${REPO_URL}
  --workdir DIR          Working directory. Default: ${WORKDIR}
  --build-type TYPE      Release, Debug, RelWithDebInfo, or MinSizeRel. Default: ${BUILD_TYPE}
  --jobs N               Parallel build jobs. Default: nproc
  --install-dir DIR      Copy the resulting clang-format binary to DIR
  --clean                Remove the build directory for this ref before configuring
  --cmake-arg ARG        Add an extra CMake argument. Can be used multiple times.
  -h, --help             Show this help message

This script does not install dependencies. It only checks that the required tools exist.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command in PATH: '$1'"
}

version_ge() {
  local have="$1"
  local need="$2"

  [[ "$have" == "$need" ]] && return 0
  [[ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n1)" == "$need" ]]
}

sanitize_ref() {
  echo "$1" | sed -E 's#[^A-Za-z0-9._-]+#_#g'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_URL="${2:-}"
      shift 2
      ;;
    --workdir)
      WORKDIR="${2:-}"
      shift 2
      ;;
    --build-type)
      BUILD_TYPE="${2:-}"
      shift 2
      ;;
    --jobs)
      JOBS="${2:-}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --clean)
      CLEAN=1
      shift
      ;;
    --cmake-arg)
      CMAKE_EXTRA_ARGS+=("${2:-}")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      die "Unknown option: $1"
      ;;
    *)
      if [[ -n "$REF" ]]; then
        die "Only one branch or tag is accepted. Already got: '$REF', received: '$1'"
      fi
      REF="$1"
      shift
      ;;
  esac
done

[[ -n "$REF" ]] || {
  echo "No ref specified, using default: llvmorg-22.1.4"
  REF="llvmorg-22.1.4"
}

[[ "$JOBS" =~ ^[0-9]+$ ]] || die "--jobs must be numeric"
[[ "$JOBS" -ge 1 ]] || die "--jobs must be >= 1"

case "$BUILD_TYPE" in
  Release|Debug|RelWithDebInfo|MinSizeRel) ;;
  *) die "Invalid --build-type: $BUILD_TYPE" ;;
esac

need_cmd git
need_cmd cmake
need_cmd ninja
need_cmd cc
need_cmd c++

CMAKE_VERSION="$(cmake --version | awk 'NR==1 {print $3}')"
version_ge "$CMAKE_VERSION" "3.20.0" || die "CMake >= 3.20.0 is required; found: $CMAKE_VERSION"

mkdir -p "$WORKDIR"

SRC_DIR="${WORKDIR}/llvm-project"
SAFE_REF="$(sanitize_ref "$REF")"
BUILD_DIR="${WORKDIR}/build-${SAFE_REF}-${BUILD_TYPE}"

echo "==> Repository:  $REPO_URL"
echo "==> Ref:         $REF"
echo "==> Source dir:  $SRC_DIR"
echo "==> Build dir:   $BUILD_DIR"
echo "==> Build type:  $BUILD_TYPE"
echo "==> Jobs:        $JOBS"

if [[ ! -d "$SRC_DIR/.git" ]]; then
  echo "==> Cloning llvm-project..."
  git clone --filter=blob:none --no-checkout "$REPO_URL" "$SRC_DIR"
else
  echo "==> Reusing existing checkout..."
  git -C "$SRC_DIR" remote set-url origin "$REPO_URL"

  if [[ -n "$(git -C "$SRC_DIR" status --porcelain)" ]]; then
    die "The checkout has local changes. Clean it or use a different --workdir."
  fi
fi

echo "==> Resolving branch/tag '$REF'..."

if git -C "$SRC_DIR" ls-remote --exit-code --heads origin "$REF" >/dev/null 2>&1; then
  echo "==> '$REF' detected as a branch"
  git -C "$SRC_DIR" fetch --depth 1 origin "refs/heads/${REF}:refs/remotes/origin/${REF}"
  git -C "$SRC_DIR" checkout --detach "refs/remotes/origin/${REF}"
elif git -C "$SRC_DIR" ls-remote --exit-code --tags origin "$REF" >/dev/null 2>&1; then
  echo "==> '$REF' detected as a tag"
  git -C "$SRC_DIR" fetch --depth 1 origin "refs/tags/${REF}:refs/tags/${REF}"
  git -C "$SRC_DIR" checkout --detach "refs/tags/${REF}"
else
  echo "==> Not an exact branch/tag name; trying direct fetch..."
  git -C "$SRC_DIR" fetch --depth 1 origin "$REF"
  git -C "$SRC_DIR" checkout --detach FETCH_HEAD
fi

COMMIT="$(git -C "$SRC_DIR" rev-parse --short=12 HEAD)"
echo "==> Commit: $COMMIT"

if [[ "$CLEAN" -eq 1 ]]; then
  echo "==> Removing build directory..."
  rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"

echo "==> Configuring CMake..."
cmake \
  -S "$SRC_DIR/llvm" \
  -B "$BUILD_DIR" \
  -G Ninja \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  -DLLVM_ENABLE_PROJECTS="clang" \
  -DLLVM_TARGETS_TO_BUILD="host" \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DCLANG_ENABLE_ARCMT=OFF \
  -DCLANG_ENABLE_STATIC_ANALYZER=OFF \
  -DLLVM_ENABLE_ZLIB=OFF \
  -DLLVM_ENABLE_ZSTD=OFF \
  -DLLVM_ENABLE_LIBXML2=OFF \
  -DLLVM_ENABLE_TERMINFO=OFF \
  "${CMAKE_EXTRA_ARGS[@]}"

echo "==> Building clang-format target..."
cmake --build "$BUILD_DIR" --target clang-format --parallel "$JOBS"

BIN="${BUILD_DIR}/bin/clang-format"
[[ -x "$BIN" ]] || die "Expected binary was not found: $BIN"

echo "==> Generated binary:"
echo "$BIN"

"$BIN" --version || true

if [[ -n "$INSTALL_DIR" ]]; then
  mkdir -p "$INSTALL_DIR"
  cp "$BIN" "$INSTALL_DIR/clang-format"
  chmod +x "$INSTALL_DIR/clang-format"
  echo "==> Copied to:"
  echo "${INSTALL_DIR}/clang-format"
fi

echo "==> Done"
