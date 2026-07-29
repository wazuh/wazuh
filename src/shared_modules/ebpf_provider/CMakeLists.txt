cmake_minimum_required(VERSION 3.12.4)

project(rt_engine C)

# eBPF Module (#37396) — standalone, consumer-agnostic engine. Builds two
# artifacts: the compiled BPF object (rt_file.bpf.o, loaded at runtime via
# bpf_object__open_file(), not a generated skeleton) and the userspace
# loader library (librt_engine) exposing rt_open()/rt_poll()/rt_close().
#
# Linked by src/syscheckd/src/ebpf/ (FIM) as of the #37396/#37533 cutover.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "eBPF Module (rt_engine) is Linux-only; skipping on ${CMAKE_SYSTEM_NAME}.")
  return()
endif()

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)
find_program(CLANG_EXECUTABLE clang REQUIRED)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  set(RT_BPF_ARCH arm64)
else()
  set(RT_BPF_ARCH x86)
endif()

set(RT_VMLINUX_H ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
set(RT_BPF_OBJ ${CMAKE_BINARY_DIR}/lib/rt_file.bpf.o)

# vmlinux.h is generated from the BUILD machine's own running kernel BTF —
# same approach spike-37396's PoC and this engine's validation build both
# already use. This means rt_file.bpf.o is most reliable when built on (or
# for) the same kernel it will run on; cross-kernel CO-RE portability of the
# generated header is a real but separate concern from this pass's scope.
add_custom_command(
  OUTPUT ${RT_VMLINUX_H}
  COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c > ${RT_VMLINUX_H}
  COMMENT "Generating vmlinux.h from the build host's kernel BTF"
)

add_custom_command(
  OUTPUT ${RT_BPF_OBJ}
  COMMAND ${CLANG_EXECUTABLE} -O2 -g -target bpf -D__TARGET_ARCH_${RT_BPF_ARCH}
          -I${CMAKE_CURRENT_SOURCE_DIR}/include
          -I${CMAKE_CURRENT_BINARY_DIR}
          -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/rt_file.bpf.c
          -o ${RT_BPF_OBJ}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/rt_file.bpf.c
          ${CMAKE_CURRENT_SOURCE_DIR}/include/rt_event_contract.h
          ${RT_VMLINUX_H}
  COMMENT "Compiling rt_file.bpf.c (eBPF Module FILE event class hooks)"
)

add_custom_target(rt_file_bpf_object ALL DEPENDS ${RT_BPF_OBJ})

add_library(rt_engine STATIC src/rt_engine.c)
target_include_directories(rt_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# libbpf is dlopen()'d at rt_open() time (see rt_engine.c's top comment) —
# no -lbpf here on purpose. -ldl for dlopen/dlsym/dlclose/dlerror.
target_link_libraries(rt_engine PUBLIC dl)
add_dependencies(rt_engine rt_file_bpf_object)

if(UNIT_TEST)
  # No unit tests yet for this newly-extracted engine — see the parent
  # analysis doc (spike-37533/) for why a rt_open()/rt_poll() mock seam is
  # the natural next addition once this is consumed by a real caller.
endif()
