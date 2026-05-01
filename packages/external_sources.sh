# Wazuh external dependency source manifest.
#
# This file is sourced by packages/build_external.sh inside the package builder
# containers. Each entry below registers one dependency and tells the script how
# to fetch a fresh upstream tarball for it when the user provides a new version.
#
# Schema (positional args to _reg):
#   name           Manifest key. Must match the input passed by the workflow
#                  (the "<name>" in "name:version;...").
#   url            Tarball URL template. {version} is substituted with the
#                  user-provided version. {version_us} is substituted with the
#                  same version with dots replaced by underscores (only used by
#                  a couple of upstream URL conventions).
#   format         Archive format. One of: tar.gz, tar.bz2, tar.xz, zip.
#   strip          Number passed to `tar --strip-components` when extracting
#                  into src/external/<target_dir>/. Almost always 1 (the
#                  upstream tarball has a versioned top-level dir).
#   target_dir     Directory under src/external/ that gets wiped and replaced
#                  with the new source. Equals <name> for almost every entry.
#   linux_only     "true" if the dep is filtered out on macOS/Windows legs by
#                  src/Makefile (currently: libbpf-bootstrap, dbus). Other deps
#                  are built on every platform the leg supports.
#   repo           Upstream project URL. Informational, matches README.md.
#
# Notes:
#   - No default versions are stored here. The workflow input must name a
#     version for every dep that is being updated. Deps not named in the input
#     are rebuilt from whatever is currently vendored under src/external/.
#   - cpython is intentionally excluded. Its build is special-cased in
#     src/Makefile (lines 535-567) and install.sh (OPTIMIZE_CPYTHON); add it
#     here only after that handling is generalized.
#   - geo_db is a MaxMind GeoLite2 binary database, not buildable source. Its
#     URL is left TBD; populate it once the Wazuh-curated location is known.
#   - URL templates were chosen to favor official release tarballs where they
#     exist (curl.se, openssl.org, IANA) and fall back to GitHub source archives
#     (`/archive/refs/tags/...`) otherwise. Tag conventions vary per project; if
#     a bump fails to download, the URL template is the first thing to check.

declare -gA EXT_URL EXT_FORMAT EXT_STRIP EXT_TARGET EXT_LINUX_ONLY EXT_REPO

_reg() {
    local name="$1"
    EXT_URL[$name]="$2"
    EXT_FORMAT[$name]="$3"
    EXT_STRIP[$name]="$4"
    EXT_TARGET[$name]="$5"
    EXT_LINUX_ONLY[$name]="$6"
    EXT_REPO[$name]="$7"
}

# ---------------------------------------------------------------------------
# Agent dependencies (also built for the manager).
# Source: src/Makefile EXTERNAL_RES (line ~452), README.md "Software and
# libraries used" table.
# ---------------------------------------------------------------------------

_reg cJSON              "https://github.com/DaveGamble/cJSON/archive/refs/tags/v{version}.tar.gz"                                 tar.gz  1  cJSON              false  "https://github.com/DaveGamble/cJSON"
_reg curl               "https://curl.se/download/curl-{version}.tar.gz"                                                          tar.gz  1  curl               false  "https://github.com/curl/curl"
_reg libdb              "https://github.com/yasuhirokimura/db18/archive/refs/tags/v{version}.tar.gz"                              tar.gz  1  libdb              false  "https://github.com/yasuhirokimura/db18"
_reg libffi             "https://github.com/libffi/libffi/releases/download/v{version}/libffi-{version}.tar.gz"                   tar.gz  1  libffi             false  "https://github.com/libffi/libffi"
_reg libyaml            "https://github.com/yaml/libyaml/releases/download/{version}/yaml-{version}.tar.gz"                       tar.gz  1  libyaml            false  "https://github.com/yaml/libyaml"
_reg openssl            "https://www.openssl.org/source/openssl-{version}.tar.gz"                                                 tar.gz  1  openssl            false  "https://github.com/openssl/openssl"
_reg procps             "https://gitlab.com/procps-ng/procps/-/archive/v{version}/procps-v{version}.tar.gz"                       tar.gz  1  procps             false  "https://gitlab.com/procps-ng/procps"
_reg sqlite             "https://www.sqlite.org/2024/sqlite-autoconf-{version_us}00.tar.gz"                                       tar.gz  1  sqlite             false  "https://github.com/sqlite/sqlite"
_reg zlib               "https://github.com/madler/zlib/releases/download/v{version}/zlib-{version}.tar.gz"                       tar.gz  1  zlib               false  "https://github.com/madler/zlib"
_reg audit-userspace    "https://github.com/linux-audit/audit-userspace/archive/refs/tags/v{version}.tar.gz"                      tar.gz  1  audit-userspace    false  "https://github.com/linux-audit/audit-userspace"
_reg msgpack            "https://github.com/msgpack/msgpack-c/releases/download/c-{version}/msgpack-c-{version}.tar.gz"           tar.gz  1  msgpack            false  "https://github.com/msgpack/msgpack-c"
_reg bzip2              "https://github.com/libarchive/bzip2/archive/refs/tags/bzip2-{version}.tar.gz"                            tar.gz  1  bzip2              false  "https://github.com/libarchive/bzip2"
_reg nlohmann           "https://github.com/nlohmann/json/archive/refs/tags/v{version}.tar.gz"                                    tar.gz  1  nlohmann           false  "https://github.com/nlohmann/json"
_reg googletest         "https://github.com/google/googletest/archive/refs/tags/release-{version}.tar.gz"                         tar.gz  1  googletest         false  "https://github.com/google/googletest"
_reg libpcre2           "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-{version}/pcre2-{version}.tar.gz"          tar.gz  1  libpcre2           false  "https://github.com/PCRE2Project/pcre2"
_reg libplist           "https://github.com/libimobiledevice/libplist/archive/refs/tags/{version}.tar.gz"                         tar.gz  1  libplist           false  "https://github.com/libimobiledevice/libplist"
_reg pacman             "https://gitlab.archlinux.org/pacman/pacman/-/archive/v{version}/pacman-v{version}.tar.gz"                tar.gz  1  pacman             false  "https://gitlab.archlinux.org/pacman/pacman"
_reg libarchive         "https://github.com/libarchive/libarchive/releases/download/v{version}/libarchive-{version}.tar.gz"       tar.gz  1  libarchive         false  "https://github.com/libarchive/libarchive"
_reg popt               "https://github.com/rpm-software-management/popt/archive/refs/tags/popt-{version}-release.tar.gz"         tar.gz  1  popt               false  "https://github.com/rpm-software-management/popt"
_reg lua                "https://www.lua.org/ftp/lua-{version}.tar.gz"                                                            tar.gz  1  lua                false  "https://github.com/lua/lua"
_reg rpm                "https://github.com/rpm-software-management/rpm/archive/refs/tags/rpm-{version}-release.tar.gz"           tar.gz  1  rpm                false  "https://github.com/rpm-software-management/rpm"
_reg rocksdb            "https://github.com/facebook/rocksdb/archive/refs/tags/v{version}.tar.gz"                                 tar.gz  1  rocksdb            false  "https://github.com/facebook/rocksdb"
_reg lzma               "https://github.com/tukaani-project/xz/releases/download/v{version}/xz-{version}.tar.gz"                  tar.gz  1  lzma               false  "https://github.com/tukaani-project/xz"
_reg cpp-httplib        "https://github.com/yhirose/cpp-httplib/archive/refs/tags/v{version}.tar.gz"                              tar.gz  1  cpp-httplib        false  "https://github.com/yhirose/cpp-httplib"
_reg benchmark          "https://github.com/google/benchmark/archive/refs/tags/v{version}.tar.gz"                                 tar.gz  1  benchmark          false  "https://github.com/google/benchmark"
_reg libbpf-bootstrap   "https://github.com/libbpf/libbpf-bootstrap/archive/refs/tags/v{version}.tar.gz"                          tar.gz  1  libbpf-bootstrap   true   "https://github.com/libbpf/libbpf-bootstrap"
_reg dbus               "https://gitlab.freedesktop.org/dbus/dbus/-/archive/dbus-{version}/dbus-dbus-{version}.tar.gz"            tar.gz  1  dbus               true   "https://gitlab.freedesktop.org/dbus/dbus"
_reg flatbuffers        "https://github.com/google/flatbuffers/archive/refs/tags/v{version}.tar.gz"                               tar.gz  1  flatbuffers        false  "https://github.com/google/flatbuffers"

# ---------------------------------------------------------------------------
# Manager-only additions.
# Source: src/Makefile (line ~456). cpython is intentionally omitted (see
# header comment).
# ---------------------------------------------------------------------------

_reg jemalloc           "https://github.com/jemalloc/jemalloc/releases/download/{version}/jemalloc-{version}.tar.bz2"             tar.bz2 1  jemalloc           false  "https://github.com/jemalloc/jemalloc"
_reg simdjson           "https://github.com/simdjson/simdjson/archive/refs/tags/v{version}.tar.gz"                                tar.gz  1  simdjson           false  "https://github.com/simdjson/simdjson"
_reg spdlog             "https://github.com/gabime/spdlog/archive/refs/tags/v{version}.tar.gz"                                    tar.gz  1  spdlog             false  "https://github.com/gabime/spdlog"
_reg yaml-cpp           "https://github.com/jbeder/yaml-cpp/archive/refs/tags/{version}.tar.gz"                                   tar.gz  1  yaml-cpp           false  "https://github.com/jbeder/yaml-cpp"
_reg pugixml            "https://github.com/zeux/pugixml/releases/download/v{version}/pugixml-{version}.tar.gz"                   tar.gz  1  pugixml            false  "https://github.com/zeux/pugixml"
_reg libmaxminddb       "https://github.com/maxmind/libmaxminddb/releases/download/{version}/libmaxminddb-{version}.tar.gz"       tar.gz  1  libmaxminddb       false  "https://github.com/maxmind/libmaxminddb"
_reg date               "https://github.com/HowardHinnant/date/archive/refs/tags/v{version}.tar.gz"                               tar.gz  1  date               false  "https://github.com/HowardHinnant/date"
_reg fmt                "https://github.com/fmtlib/fmt/releases/download/{version}/fmt-{version}.zip"                             zip     1  fmt                false  "https://github.com/fmtlib/fmt"
_reg abseil-cpp         "https://github.com/abseil/abseil-cpp/archive/refs/tags/{version}.tar.gz"                                 tar.gz  1  abseil-cpp         false  "https://github.com/abseil/abseil-cpp"
_reg re2                "https://github.com/google/re2/archive/refs/tags/{version}.tar.gz"                                        tar.gz  1  re2                false  "https://github.com/google/re2"
_reg protobuf           "https://github.com/protocolbuffers/protobuf/releases/download/v{version}/protobuf-{version}.tar.gz"      tar.gz  1  protobuf           false  "https://github.com/protocolbuffers/protobuf"
_reg rapidjson          "https://github.com/Tencent/rapidjson/archive/refs/tags/v{version}.tar.gz"                                tar.gz  1  rapidjson          false  "https://github.com/Tencent/rapidjson"
_reg taskflow           "https://github.com/taskflow/taskflow/archive/refs/tags/v{version}.tar.gz"                                tar.gz  1  taskflow           false  "https://github.com/taskflow/taskflow"
_reg RxCpp              "https://github.com/ReactiveX/RxCpp/archive/refs/tags/v{version}.tar.gz"                                  tar.gz  1  RxCpp              false  "https://github.com/ReactiveX/RxCpp"
_reg concurrentqueue    "https://github.com/cameron314/concurrentqueue/archive/refs/tags/v{version}.tar.gz"                       tar.gz  1  concurrentqueue    false  "https://github.com/cameron314/concurrentqueue"
_reg fast_float         "https://github.com/fastfloat/fast_float/archive/refs/tags/v{version}.tar.gz"                             tar.gz  1  fast_float         false  "https://github.com/fastfloat/fast_float"
_reg tzdata             "https://data.iana.org/time-zones/releases/tzdata{version}.tar.gz"                                        tar.gz  0  tzdata             false  "https://data.iana.org/time-zones/"
_reg geo_db             "TBD"                                                                                                     tar.gz  0  geo_db             false  "https://www.maxmind.com/"

# Sanity check: warn if any registered name has no corresponding directory in
# src/external/. The script can decide whether to error or just log; this is
# informational. Skipped at source-time (no side effects beyond array writes).
