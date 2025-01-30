if(NOT USE_BUNDLED_FALCOSECURITY_LIBS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSINSP REQUIRED IMPORTED_TARGET libsinsp>=0.20.0)
    message(STATUS "Found libsinsp:
  include: ${LIBSINSP_INCLUDE_DIRS}
  lib: ${LIBSINSP_LIBRARIES}
  cflags: ${LIBSINSP_CFLAGS}")
    return()
endif()

# else(): using bundled falcosecurity libs
set(FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/falcosecurity-libs-repo")
set(FALCOSECURITY_LIBS_CMAKE_WORKING_DIR "${CMAKE_BINARY_DIR}/falcosecurity-libs-repo")

file(MAKE_DIRECTORY ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR})

# explicitly disable the bundled driver, since we pull it separately
set(USE_BUNDLED_DRIVER OFF CACHE BOOL "")

if(FALCOSECURITY_LIBS_SOURCE_DIR)
  set(FALCOSECURITY_LIBS_VERSION "0.0.0-local")
  message(STATUS "Using local version of falcosecurity/libs: '${FALCOSECURITY_LIBS_SOURCE_DIR}'")
else()
  # FALCOSECURITY_LIBS_VERSION accepts a git reference (branch name, commit hash, or tag) to the falcosecurity/libs repository.
  # In case you want to test against another falcosecurity/libs version (or branch, or commit) just pass the variable -
  # ie., `cmake -DFALCOSECURITY_LIBS_VERSION=dev ..`
  if(NOT FALCOSECURITY_LIBS_VERSION)
    set(FALCOSECURITY_LIBS_VERSION "0.20.0")
    set(FALCOSECURITY_LIBS_CHECKSUM "SHA256=4ae6ddb42a1012bacd88c63abdaa7bd27ca0143c4721338a22c45597e63bc99d")
  endif()

  # cd /path/to/build && cmake /path/to/source
  execute_process(COMMAND "${CMAKE_COMMAND}" -DFALCOSECURITY_LIBS_VERSION=${FALCOSECURITY_LIBS_VERSION} -DFALCOSECURITY_LIBS_CHECKSUM=${FALCOSECURITY_LIBS_CHECKSUM}
    ${FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR} WORKING_DIRECTORY ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR})

  execute_process(COMMAND "${CMAKE_COMMAND}" --build . WORKING_DIRECTORY "${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}")
  set(FALCOSECURITY_LIBS_SOURCE_DIR "${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}/falcosecurity-libs-prefix/src/falcosecurity-libs")
endif()

set(LIBS_PACKAGE_NAME "sysdig")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  add_definitions(-D_GNU_SOURCE)
  add_definitions(-DHAS_CAPTURE)
endif()

if(MUSL_OPTIMIZED_BUILD)
  add_definitions(-DMUSL_OPTIMIZED)
endif()

set(SCAP_HOST_ROOT_ENV_VAR_NAME "HOST_ROOT")

if(NOT LIBS_DIR)
   set(LIBS_DIR "${FALCOSECURITY_LIBS_SOURCE_DIR}")
 endif()

# configure gVisor support
set(BUILD_LIBSCAP_GVISOR ${BUILD_SYSDIG_GVISOR} CACHE BOOL "")

# configure modern BPF support
set(BUILD_LIBSCAP_MODERN_BPF ${BUILD_SYSDIG_MODERN_BPF} CACHE BOOL "")

set(WITH_CHISEL ON CACHE INTERNAL "" FORCE)
set(CHISEL_TOOL_LIBRARY_NAME "sysdig")

set(USE_BUNDLED_LIBELF OFF CACHE BOOL "")
set(USE_BUNDLED_TBB OFF CACHE BOOL "")
set(USE_BUNDLED_B64 ON CACHE BOOL "")
set(USE_BUNDLED_JSONCPP ON CACHE BOOL "")
set(USE_BUNDLED_VALIJSON ON CACHE BOOL "")
set(USE_BUNDLED_RE2 ON CACHE BOOL "")
set(CREATE_TEST_TARGETS OFF CACHE BOOL "")

list(APPEND CMAKE_MODULE_PATH "${FALCOSECURITY_LIBS_SOURCE_DIR}/cmake/modules")

include(CheckSymbolExists)
check_symbol_exists(strlcpy "string.h" HAVE_STRLCPY)

if(HAVE_STRLCPY)
  message(STATUS "Existing strlcpy found, will *not* use local definition by setting -DHAVE_STRLCPY.")
  add_definitions(-DHAVE_STRLCPY)
else()
  message(STATUS "No strlcpy found, will use local definition")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

include(driver)
include(libscap)
include(libsinsp)
