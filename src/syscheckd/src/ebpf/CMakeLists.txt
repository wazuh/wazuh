cmake_minimum_required(VERSION 3.12.4)

# Set the project name
project(fimebpf)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/libbpf-bootstrap/build/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../db/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../ebpf/include/)
include_directories(${SRC_FOLDER}/external/libpcre2/include/)
include_directories(${SRC_FOLDER}/shared/os_regex/)
include_directories(${SRC_FOLDER}/shared/include/)
# #37532: container-baseline module (host-side FIM baseline for containers).
include_directories(${SRC_FOLDER}/wazuh_modules/container_baseline/include/)
# #37533: live container FIM needs the container_instances query client
# directly (container_baseline's own CMakeLists only re-exposes its own
# public C API header, not this one, via plain include_directories()).
include_directories(${SRC_FOLDER}/shared_modules/container_instances_client/include/)
# #37396: the eBPF Module engine FIM now consumes instead of loading libbpf itself.
include_directories(${SRC_FOLDER}/shared_modules/ebpf_provider/include/)

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(fimebpf SHARED src/ebpf_whodata.cpp src/container_baseline_fim.cpp src/container_baseline_fim_bridge.c src/container_live_fim.cpp ../persist_syscheck_msg.c)

# Link against wazuh, the container-baseline module (#37532), and the
# standalone eBPF Module engine (#37396) — fimebpf no longer loads libbpf
# or the FIM BPF object itself, see ebpf_whodata.cpp's top comment.
target_link_libraries(fimebpf PRIVATE wazuh container_baseline rt_engine)

# Set additional compile flags for the loader (if needed)
target_compile_options(fimebpf PRIVATE -Wall -Wextra)

if(UNIT_TEST)
  # Use PRIVATE coverage for eBPF to avoid ODR violations with test executables
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(fimebpf PRIVATE --coverage)
    target_link_libraries(fimebpf PRIVATE -fprofile-arcs)
  else()
    target_compile_options(fimebpf PRIVATE --coverage)
    target_link_libraries(fimebpf PRIVATE gcov)
  endif()
  add_subdirectory(tests/fimEbpfWhodataTest)
  add_subdirectory(tests/unit)
endif(UNIT_TEST)
