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

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  set(RT_BPF_ARCH arm64)
else()
  set(RT_BPF_ARCH x86)
endif()

set(RT_BPF_OBJ ${CMAKE_BINARY_DIR}/lib/rt_file.bpf.o)
set(RT_BPF_PREBUILT ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/rt_file.bpf.o)

# The portable, per-architecture vmlinux.h the existing pipeline already uses
# (fetched by external/libbpf-bootstrap's vmlinux.h ExternalProject). Preferred
# over dumping the build host's own BTF, which yields an object most reliable
# only on the kernel it was built against. Note it is absent whenever a prebuilt
# modern.bpf.o short-circuits that ExternalProject, which is the common case.
set(RT_VMLINUX_VENDORED
    ${SRC_FOLDER}/external/libbpf-bootstrap/vmlinux.h/include/${RT_BPF_ARCH}/vmlinux.h)

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

if(EXISTS ${RT_BPF_PREBUILT})

  message(STATUS "eBPF Module: using prebuilt rt_file.bpf.o")
  add_custom_command(
    OUTPUT ${RT_BPF_OBJ}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RT_BPF_PREBUILT} ${RT_BPF_OBJ}
    DEPENDS ${RT_BPF_PREBUILT}
    COMMENT "Installing prebuilt rt_file.bpf.o")
  add_custom_target(rt_file_bpf_object ALL DEPENDS ${RT_BPF_OBJ})

elseif(CLANG_EXECUTABLE AND RT_LIBBPF_HEADER_DIR AND (EXISTS ${RT_VMLINUX_VENDORED} OR RT_BPFTOOL_USABLE))

  if(EXISTS ${RT_VMLINUX_VENDORED})
    set(RT_VMLINUX_INCLUDE_DIR ${SRC_FOLDER}/external/libbpf-bootstrap/vmlinux.h/include/${RT_BPF_ARCH})
    set(RT_VMLINUX_H ${RT_VMLINUX_VENDORED})
    message(STATUS "eBPF Module: compiling rt_file.bpf.o against the vendored ${RT_BPF_ARCH} vmlinux.h")
  else()
    # Fallback: dump the BUILD machine's own running-kernel BTF. Works, but the
    # resulting object is most reliable on that same kernel — cross-kernel CO-RE
    # portability of a host-generated header is a real, separate concern.
    set(RT_VMLINUX_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(RT_VMLINUX_H ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
    message(STATUS "eBPF Module: vendored vmlinux.h absent; generating one from this host's kernel BTF")
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
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/rt_file.bpf.c
            ${CMAKE_CURRENT_SOURCE_DIR}/include/rt_event_contract.h
            ${RT_VMLINUX_H}
    COMMENT "Compiling rt_file.bpf.c (eBPF Module FILE event class hooks)")
  add_custom_target(rt_file_bpf_object ALL DEPENDS ${RT_BPF_OBJ})

else()

  # Not an error: librt_engine still builds and links. rt_open() will simply
  # find no object at runtime and return NULL, which every caller must already
  # handle as "eBPF unavailable".
  set(RT_BPF_SKIP_REASON "")
  if(NOT CLANG_EXECUTABLE)
    string(APPEND RT_BPF_SKIP_REASON " clang not found;")
  endif()
  if(NOT RT_LIBBPF_HEADER_DIR)
    string(APPEND RT_BPF_SKIP_REASON " bpf/bpf_helpers.h not found (no libbpf headers);")
  endif()
  if(NOT EXISTS ${RT_VMLINUX_VENDORED} AND NOT RT_BPFTOOL_USABLE)
    string(APPEND RT_BPF_SKIP_REASON " no vendored vmlinux.h and no usable bpftool;")
  endif()
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
  add_test(NAME rt_engine_contract_test COMMAND rt_engine_contract_test)
endif()
