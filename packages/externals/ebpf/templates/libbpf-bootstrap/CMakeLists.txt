# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.10)

# Set the project name
project(libbpf_boostrap)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)

# Build vendored libbpf
# Clone libbpf repository
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  GIT_REPOSITORY https://github.com/libbpf/libbpf.git
  GIT_TAG v1.7.0  # v1.4.0: f11758a7807893330cc87481a7a16cf956326ab3
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf
  CONFIGURE_COMMAND ""
  BUILD_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src && make CFLAGS="-fPIC${CFLAGS}" LDFLAGS="-lelf${LDFLAGS}"
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# Clone bpftool repository
ExternalProject_Add(bpftool
  PREFIX bpftool
  GIT_REPOSITORY https://github.com/libbpf/bpftool.git
  GIT_TAG v7.7.0
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool
  CONFIGURE_COMMAND ""
  BUILD_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src && make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# Clone vmlinux.h repository
ExternalProject_Add(vmlinux.h
  PREFIX vmlinux.h
  GIT_REPOSITORY https://github.com/libbpf/vmlinux.h.git
  GIT_TAG main
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
)

# Set the path to clang (update if necessary)
set(CLANG_PATH "/usr/bin/clang")

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64" OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "i686")
  set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm" OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "armv8l")
  set(ARCH "arm")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
  set(ARCH "arm64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
  set(ARCH "powerpc")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
  set(ARCH "mips")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
  set(ARCH "riscv")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
  set(ARCH "loongarch")
endif()

# Set the branch of the Wazuh repository as a cache variable
set(WAZUH_BRANCH "v4.12.0" CACHE STRING "Wazuh branch for modern.bpf.c")

# Download modern.bpf.c with error checking that verifies file existence and non-zero size
set(FILE_URL "https://raw.githubusercontent.com/wazuh/wazuh/${WAZUH_BRANCH}/src/syscheckd/src/ebpf/src/modern.bpf.c")
set(DEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/modern.bpf.c")
file(DOWNLOAD ${FILE_URL} ${DEST_PATH})
file(SIZE ${DEST_PATH} FILE_SIZE)
if(NOT EXISTS ${DEST_PATH} OR FILE_SIZE EQUAL 0)
    message(FATAL_ERROR "Failed to download modern.bpf.c from ${FILE_URL}. Please check WAZUH_BRANCH.")
endif()

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h/include/${ARCH}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h/include/${ARCH}
)

bpf_object(modern src/modern.bpf.c)
add_dependencies(modern_skel libbpf-build bpftool-build vmlinux.h)

add_library(modern SHARED src/modern.bpf.c)
target_link_libraries(modern modern_skel)

add_custom_target(change_libbpf_include ALL
  COMMAND sed -i 's|<bpf/libbpf.h>|"wrapper_bpf.h"|' ${CMAKE_CURRENT_BINARY_DIR}/modern.skel.h
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/modern.skel.h
  COMMENT "Change libbpf include by wrapper_bpf.h from skeleton"
)
