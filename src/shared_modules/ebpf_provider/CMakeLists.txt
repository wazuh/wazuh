cmake_minimum_required(VERSION 3.12.4)

project(rt_engine C)

# eBPF Module (#37396) — standalone, consumer-agnostic engine. Builds two
# artifacts: the compiled BPF object (rt_file.bpf.o, loaded at runtime via
# bpf_object__open_file(), not a generated skeleton) and the userspace
# loader library (librt_engine) exposing rt_open()/rt_poll()/rt_close().
#
# Nothing consumes it yet: this lands the engine so it builds and can be
# validated on its own, ahead of any caller (see 12-blocking-decisions.md,
# Track E). FIM still loads modern.bpf.o through its own libbpf path.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "eBPF Module (rt_engine) is Linux-only; skipping on ${CMAKE_SYSTEM_NAME}.")
  return()
endif()

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ------------------------------------------------------------------------------
# The userspace loader library — always built.
# ------------------------------------------------------------------------------
#
# Plain C with no dependency beyond libdl: libbpf is resolved by dlopen() at
# rt_open() time and its types are shadowed locally (rt_libbpf_shim.h), so this
# compiles anywhere, including build environments with no BPF toolchain and no
# libbpf headers. That is deliberate — the object below may be skipped, but the
# library must never be, or every consumer's link breaks on such a host.

add_library(rt_engine STATIC src/rt_engine.c)
target_include_directories(rt_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# The shared cgroup hierarchy probe (header-only, no link dependency). PRIVATE:
# it is how this library answers the question internally, not part of what it
# publishes — consumers that need the answer call rt_host_cgroup_v1(), and
# consumers that are not this library include the header themselves.
target_include_directories(rt_engine PRIVATE ${SRC_FOLDER}/shared_modules/common)

# libbpf is dlopen()'d at rt_open() time (see rt_engine.c's top comment) —
# no -lbpf here on purpose. -ldl for dlopen/dlsym/dlclose/dlerror.
target_link_libraries(rt_engine PUBLIC dl)

# This static library is linked into fimebpf, a SHARED library — without
# PIC, the final link fails ("relocation ... can not be used when making a
# shared object; recompile with -fPIC"), the same reason
# container_baseline's CMakeLists sets this for CONTAINER_BASELINE_IMPL.
set_target_properties(rt_engine PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ------------------------------------------------------------------------------
# The BPF object — built when it can be, skipped when it cannot.
# ------------------------------------------------------------------------------
#
# Three-way gate, mirroring how src/external/CMakeLists.txt already treats
# modern.bpf.o: prefer a prebuilt object, else compile it if the toolchain AND a
# vmlinux.h are both available, else skip with a diagnostic.
#
# `find_program(... REQUIRED)` is deliberately NOT used. A hard requirement here
# fails at configure time, which breaks the build of the whole agent — including
# in the WSL environment this branch is developed in, where neither clang, nor
# bpftool, nor any vmlinux.h is present. A missing BPF object degrades to
# "eBPF unavailable at runtime", which the engine already handles (rt_open()
# returns NULL); a failed configure degrades to nothing building at all.

# Only the two architectures an object is actually produced for. This used to
# map EVERYTHING that was not aarch64 to x86, which quietly handed a 32-bit
# i386 build an object compiled with -D__TARGET_ARCH_x86 against an x86_64
# vmlinux.h: wrong pt_regs offsets, so it would be installed and then fail to
# load, and that failure is indistinguishable from "this host has no eBPF".
# Anything else now gets no object at all, which is the honest outcome and the
# one the engine already degrades to cleanly.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  set(RT_BPF_ARCH arm64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
  set(RT_BPF_ARCH x86)
else()
  set(RT_BPF_ARCH "")
endif()

set(RT_BPF_OBJ ${CMAKE_BINARY_DIR}/lib/rt_file.bpf.o)

# PER-ARCHITECTURE, and this is not cosmetic. A BPF object is compiled against
# one architecture's vmlinux.h with -D__TARGET_ARCH_<arch>, so an x86 object is
# not loadable on arm64 — the CO-RE relocations and the pt_regs field offsets
# are both wrong. A single arch-blind prebuilt/rt_file.bpf.o would be copied
# into place on every build host and fail to load on half of them, and the
# runtime failure looks exactly like "no eBPF here", which is the one thing
# this path degrades to silently.
#
# To refresh one, see prebuilt/README.md. Note that NO arch toolchain is needed
# for the other architecture: a BPF object is architecture-independent ELF, and
# the only arch-dependent inputs are -D__TARGET_ARCH_<arch> and which vmlinux.h
# is on the include path. What is needed is that architecture's vmlinux.h, and
# the vendored one cannot supply it -- it defines no cgroup types at all, so
# rt_file.bpf.c does not compile against it on either arch. Dump a real host's
# BTF instead (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`), which
# needs no root and can even be done on a host of the *other* architecture,
# since BTF parsing is itself arch-independent.
set(RT_BPF_PREBUILT ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${RT_BPF_ARCH}/rt_file.bpf.o)

# The portable, per-architecture vmlinux.h the existing pipeline already uses
# (fetched by external/libbpf-bootstrap's vmlinux.h ExternalProject). Preferred
# over dumping the build host's own BTF, which yields an object most reliable
# only on the kernel it was built against. Note it is absent whenever a prebuilt
# modern.bpf.o short-circuits that ExternalProject, which is the common case.
set(RT_VMLINUX_VENDORED
    ${SRC_FOLDER}/external/libbpf-bootstrap/vmlinux.h/include/${RT_BPF_ARCH}/vmlinux.h)

# Existing is not the same as usable. The vendored header is a REDUCED dump: it
# defines no cgroup types at all -- no struct cgroup, no css_set, no
# cgroup_subsys_state -- and its task_struct has no `cgroups` member, on x86 and
# arm64 alike. rt_file.bpf.c cannot compile against it, so preferring it merely
# because it is present guarantees a failed build on every host that has it.
# (Beware a misleading grep: `css_set *cgroups` does appear in that file, but
# inside struct task_struct__safe_rcu, not task_struct.)
#
# Probe for one type the program actually needs, so this corrects itself if the
# vendored header is ever fixed, rather than staying hardcoded to today's fault.
set(RT_VMLINUX_VENDORED_USABLE FALSE)
if(RT_BPF_ARCH AND EXISTS ${RT_VMLINUX_VENDORED})
  file(STRINGS ${RT_VMLINUX_VENDORED} RT_VMLINUX_CSS_SET
       REGEX "^struct css_set \\{" LIMIT_COUNT 1)
  if(RT_VMLINUX_CSS_SET)
    set(RT_VMLINUX_VENDORED_USABLE TRUE)
  endif()
endif()

find_program(BPFTOOL_EXECUTABLE bpftool)
find_program(CLANG_EXECUTABLE clang)

# rt_file.bpf.c includes <bpf/bpf_helpers.h> and friends, which come from a
# libbpf development package rather than from this tree (the deps tarball ships
# libbpf.so/.a only). Without them clang cannot compile the object.
find_path(RT_LIBBPF_HEADER_DIR bpf/bpf_helpers.h)

# find_program() finding "bpftool" is not the same as having a working bpftool:
# Debian/Ubuntu ship /usr/sbin/bpftool as a kernel-version dispatch stub that
# exits non-zero with "bpftool not found for kernel ..." when no matching
# linux-tools package is installed — which is exactly the case in the WSL
# environment this branch is developed in. Probe it instead of trusting the path,
# and require the kernel BTF it would read.
set(RT_BPFTOOL_USABLE FALSE)
if(BPFTOOL_EXECUTABLE AND EXISTS /sys/kernel/btf/vmlinux)
  execute_process(COMMAND ${BPFTOOL_EXECUTABLE} version
                  RESULT_VARIABLE RT_BPFTOOL_PROBE_RC
                  OUTPUT_QUIET ERROR_QUIET)
  if(RT_BPFTOOL_PROBE_RC EQUAL 0)
    set(RT_BPFTOOL_USABLE TRUE)
  endif()
endif()

if(RT_BPF_ARCH AND EXISTS ${RT_BPF_PREBUILT})

  # Nothing detects an object left behind by an earlier version of the source,
  # and the prebuilt is PREFERRED over compiling -- so without this a developer
  # editing rt_file.bpf.c would keep shipping the old binary and never be told.
  # The digest covers the two files the object is built from.
  file(SHA256 ${CMAKE_CURRENT_SOURCE_DIR}/bpf/rt_file.bpf.c RT_BPF_SRC_HASH)
  file(SHA256 ${CMAKE_CURRENT_SOURCE_DIR}/include/rt_event_contract.h RT_BPF_ABI_HASH)
  set(RT_BPF_SOURCES_DIGEST "${RT_BPF_SRC_HASH} ${RT_BPF_ABI_HASH}")
  set(RT_BPF_DIGEST_FILE ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${RT_BPF_ARCH}/rt_file.bpf.o.sources.sha256)

  set(RT_BPF_RECORDED_DIGEST "")
  if(EXISTS ${RT_BPF_DIGEST_FILE})
    file(READ ${RT_BPF_DIGEST_FILE} RT_BPF_RECORDED_DIGEST)
    string(STRIP "${RT_BPF_RECORDED_DIGEST}" RT_BPF_RECORDED_DIGEST)
  endif()

  # A stale prebuilt is a WARNING for a developer and an ERROR for anything that
  # produces artifacts other people run. The warning alone kept the build green,
  # and a package build would then ship an object that does not correspond to
  # rt_file.bpf.c at all -- the one outcome this guard exists to prevent.
  #
  # ON by default, and deliberately NOT keyed off the environment.
  #
  # It was keyed off CI, on the reasoning that a pipeline sets it and a
  # developer does not. That reached the wrong builds. The .deb and .rpm are
  # produced inside a container started by packages/generate_package.sh, which
  # forwards a fixed list of variables -- SYSTEM, BUILD_TARGET,
  # ARCHITECTURE_TARGET, INSTALLATION_PATH, IS_STAGE, WAZUH_BRANCH,
  # WAZUH_VERBOSE -- and CI is not among them. So the runner's CI reached the
  # jobs whose output is thrown away and not the one whose output ships, which
  # is the exact inverse of the intent.
  #
  # Defaulting ON removes the plumbing from the question: there is no
  # environment to forward and no build script to remember. A stale object now
  # fails everywhere unless someone says otherwise, which is the right default
  # for a binary that is PREFERRED over compiling -- left to a warning, an edit
  # to rt_file.bpf.c silently ships the old object.
  #
  # -DRT_BPF_STRICT_PREBUILT=OFF is the opt-out, for a developer mid-edit who
  # has not refreshed the digest yet.
  option(RT_BPF_STRICT_PREBUILT
         "Fail the build when prebuilt rt_file.bpf.o does not match its sources" ON)

  if(NOT RT_BPF_RECORDED_DIGEST STREQUAL RT_BPF_SOURCES_DIGEST)
    set(RT_BPF_STALE_MESSAGE
        "eBPF Module: prebuilt/${RT_BPF_ARCH}/rt_file.bpf.o is STALE -- it was built from a "
        "different bpf/rt_file.bpf.c or include/rt_event_contract.h than the one in this tree, "
        "and it is preferred over compiling, so that is the object that will ship. "
        "Rebuild it and refresh the digest: see prebuilt/README.md.")
    if(RT_BPF_STRICT_PREBUILT)
      message(FATAL_ERROR ${RT_BPF_STALE_MESSAGE})
    else()
      message(WARNING ${RT_BPF_STALE_MESSAGE})
    endif()
  endif()

  # What the object was built with. NOT part of the digest above: these are
  # properties of whichever host produced the binary, so comparing them would
  # make the check fail on every machine but that one. Recorded and printed so a
  # rebuild can be reproduced, which is the actual need.
  set(RT_BPF_PROVENANCE_FILE
      ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${RT_BPF_ARCH}/rt_file.bpf.o.provenance)
  if(EXISTS ${RT_BPF_PROVENANCE_FILE})
    file(READ ${RT_BPF_PROVENANCE_FILE} RT_BPF_PROVENANCE)
    string(STRIP "${RT_BPF_PROVENANCE}" RT_BPF_PROVENANCE)
    message(STATUS "eBPF Module: prebuilt ${RT_BPF_ARCH} rt_file.bpf.o provenance: ${RT_BPF_PROVENANCE}")
  else()
    message(WARNING
            "eBPF Module: prebuilt/${RT_BPF_ARCH}/rt_file.bpf.o has no .provenance file, so the "
            "clang version and kernel BTF it was built from are unrecorded and the object cannot "
            "be reproduced. See prebuilt/README.md.")
  endif()

  message(STATUS "eBPF Module: using prebuilt ${RT_BPF_ARCH} rt_file.bpf.o")
  add_custom_command(
    OUTPUT ${RT_BPF_OBJ}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RT_BPF_PREBUILT} ${RT_BPF_OBJ}
    # The prebuilt is the object that actually ships, so it is the one that has
    # to hold the .text invariant. Checking only the compiled branch left the
    # shipped binary as the single unchecked path.
    COMMAND ${CMAKE_COMMAND} -E env RT_BPF_SYMBOLS_REQUIRED=$<IF:$<BOOL:${RT_BPF_STRICT_PREBUILT}>,1,0>
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_bpf_symbols.sh ${RT_BPF_OBJ}
    DEPENDS ${RT_BPF_PREBUILT}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_bpf_symbols.sh
    COMMENT "Installing prebuilt rt_file.bpf.o")
  add_custom_target(rt_file_bpf_object ALL DEPENDS ${RT_BPF_OBJ})

elseif(RT_BPF_ARCH AND CLANG_EXECUTABLE AND RT_LIBBPF_HEADER_DIR AND (RT_VMLINUX_VENDORED_USABLE OR RT_BPFTOOL_USABLE))

  if(RT_VMLINUX_VENDORED_USABLE)
    set(RT_VMLINUX_INCLUDE_DIR ${SRC_FOLDER}/external/libbpf-bootstrap/vmlinux.h/include/${RT_BPF_ARCH})
    set(RT_VMLINUX_H ${RT_VMLINUX_VENDORED})
    message(STATUS "eBPF Module: compiling rt_file.bpf.o against the vendored ${RT_BPF_ARCH} vmlinux.h")
  else()
    # Fallback: dump the BUILD machine's own running-kernel BTF. Works, but the
    # resulting object is most reliable on that same kernel — cross-kernel CO-RE
    # portability of a host-generated header is a real, separate concern.
    set(RT_VMLINUX_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(RT_VMLINUX_H ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
    message(STATUS "eBPF Module: no usable vendored vmlinux.h; generating one from this host's kernel BTF")
    add_custom_command(
      OUTPUT ${RT_VMLINUX_H}
      COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c > ${RT_VMLINUX_H}
      COMMENT "Generating vmlinux.h from the build host's kernel BTF")
  endif()

  add_custom_command(
    OUTPUT ${RT_BPF_OBJ}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/lib
    COMMAND ${CLANG_EXECUTABLE} -O2 -g -target bpf -D__TARGET_ARCH_${RT_BPF_ARCH}
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            -I${RT_VMLINUX_INCLUDE_DIR}
            -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/rt_file.bpf.c
            -o ${RT_BPF_OBJ}
    # Asserts that clang inlined every helper and outlined only rt_walk_dentry.
    # A build-time check and not a review item, because what it is checking is a
    # compiler decision: get it wrong and the object loads everywhere except on
    # a legacy RHEL-family kernel, which no CI job load-tests.
    COMMAND ${CMAKE_COMMAND} -E env RT_BPF_SYMBOLS_REQUIRED=1
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_bpf_symbols.sh ${RT_BPF_OBJ}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/rt_file.bpf.c
            ${CMAKE_CURRENT_SOURCE_DIR}/include/rt_event_contract.h
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_bpf_symbols.sh
            ${RT_VMLINUX_H}
    COMMENT "Compiling rt_file.bpf.c (eBPF Module FILE event class hooks)")
  add_custom_target(rt_file_bpf_object ALL DEPENDS ${RT_BPF_OBJ})

else()

  # Not an error: librt_engine still builds and links. rt_open() will simply
  # find no object at runtime and return NULL, which every caller must already
  # handle as "eBPF unavailable".
  set(RT_BPF_SKIP_REASON "")
  if(NOT RT_BPF_ARCH)
    string(APPEND RT_BPF_SKIP_REASON
           " no BPF object is produced for ${CMAKE_SYSTEM_PROCESSOR} (only x86_64 and aarch64);")
  endif()
  if(NOT CLANG_EXECUTABLE)
    string(APPEND RT_BPF_SKIP_REASON " clang not found;")
  endif()
  if(NOT RT_LIBBPF_HEADER_DIR)
    string(APPEND RT_BPF_SKIP_REASON " bpf/bpf_helpers.h not found (no libbpf headers);")
  endif()
  if(NOT RT_VMLINUX_VENDORED_USABLE AND NOT RT_BPFTOOL_USABLE)
    string(APPEND RT_BPF_SKIP_REASON " no usable vendored vmlinux.h (it defines no cgroup types) and no usable bpftool;")
  endif()
  string(APPEND RT_BPF_SKIP_REASON " no prebuilt at ${RT_BPF_PREBUILT};")
  message(STATUS "eBPF Module: skipping rt_file.bpf.o —${RT_BPF_SKIP_REASON} "
                 "librt_engine still builds, rt_open() will report eBPF unavailable at runtime.")
  add_custom_target(rt_file_bpf_object)

endif()

add_dependencies(rt_engine rt_file_bpf_object)

if(UNIT_TEST)
  # Contract tests: plain C, no gtest, no BPF object, no kernel, no root. They
  # pin the event ABI — which is exchanged by raw memory reinterpretation and so
  # has nothing else checking it — plus rt_open's filter validation, the log
  # seam and the NULL-handle contracts.
  #
  # Deliberately not gtest: these must run wherever the tree builds, and the
  # vendored googletest cannot configure under CMake 4.x (it still declares
  # cmake_minimum_required(2.8.12)). A dependency-free binary sidesteps that
  # entirely.
  #
  # Still missing, and needing a fake libbpf: every rt_open path past the filter
  # check, the per-event ABI rejection inside the ring-buffer callback, and link
  # teardown accounting (11-ebpf-provider-import-plan.md §11.9 item 9, §11.10).
  add_executable(rt_engine_contract_test test/rt_engine_contract_test.c)
  target_link_libraries(rt_engine_contract_test rt_engine)
  # rt_engine keeps the shared probe PRIVATE, so the test includes it directly
  # — which is what lets it assert the two agree rather than trusting that
  # they do.
  target_include_directories(rt_engine_contract_test PRIVATE ${SRC_FOLDER}/shared_modules/common)
  add_test(NAME rt_engine_contract_test COMMAND rt_engine_contract_test)
endif()
