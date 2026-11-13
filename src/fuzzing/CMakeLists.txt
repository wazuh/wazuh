# Fuzzing harnesses for wazuh.
#
# Opt-in: they are never built by production defaults. Enable with
#   cmake .. -DTARGET=agent -DWAZUH_BUILD_FUZZERS=ON
# OSS-Fuzz builds them with its fuzzing engine passed through the
# LIB_FUZZING_ENGINE environment variable; a local build without it falls
# back to libFuzzer (-fsanitize=fuzzer, requires clang).
#
# The harnesses link the static externals prepared by
# `make deps TARGET=agent`, mirroring the wazuh build.

set(FUZZING_OUTPUT_DIR "${CMAKE_BINARY_DIR}/fuzzing")

add_executable(fuzz_xml fuzz_xml.c)

target_include_directories(fuzz_xml PRIVATE
    ${SRC_FOLDER}
    ${SRC_FOLDER}/shared
    )

# Link the exact archives the OSS-Fuzz integration has always used (the
# project library archive plus the static externals from `make deps`), not
# the CMake target: linking the target would drag the transitive shared
# wazuhext library into the harness binary, breaking out-of-tree execution.
add_dependencies(fuzz_xml wazuh)
target_link_libraries(fuzz_xml PRIVATE
    ${CMAKE_BINARY_DIR}/lib/libwazuh.a
    ${SRC_FOLDER}/external/sqlite/libsqlite3.a
    ${SRC_FOLDER}/external/cJSON/libcjson.a
    ${SRC_FOLDER}/external/zlib/libz.a
    ${SRC_FOLDER}/external/bzip2/libbz2.a
    pthread
    dl
    rt
    m
    )

if(DEFINED ENV{LIB_FUZZING_ENGINE} AND NOT "$ENV{LIB_FUZZING_ENGINE}" STREQUAL "")
  target_link_options(fuzz_xml PRIVATE "$ENV{LIB_FUZZING_ENGINE}")
else()
  target_compile_options(fuzz_xml PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_xml PRIVATE -fsanitize=fuzzer)
endif()

set_target_properties(fuzz_xml PROPERTIES
    LINKER_LANGUAGE C
    RUNTIME_OUTPUT_DIRECTORY "${FUZZING_OUTPUT_DIR}"
    )
