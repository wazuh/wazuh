# Minimum 3.14 required by googletest discover tests
# Todo find wich component is not working properly until 3.22.1 version
cmake_minimum_required(VERSION 3.22.1 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Project settings
project(wazuh-engine
    VERSION 0.1
    LANGUAGES CXX
)

# Project folder structure
set(ENGINE_BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
# set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)
set(ENGINE_SOURCE_DIR ${PROJECT_SOURCE_DIR}/source)
set(ENGINE_DOC_DIR ${PROJECT_SOURCE_DIR}/docs)

# Options
option(ENGINE_BUILD_TEST "Generate tests" ON)
option(ENGINE_BUILD_BENCHMARK "Generate benchmarks" ON)
option(ENGINE_BUILD_DOCUMENTATION "Generate doxygen documentation" ON)
option(ENGINE_ASSERT_WITH_SYMBOLS "Exports exe symbols to have asserts with full symbolicated functions" ON)
option(ENGINE_GENERATE_PROTO "Generate protobuf code" OFF)

# TODO put this in a better place together with other global options like warnings
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(ENGINE_ASSERT_WITH_SYMBOLS)
        add_link_options ( -rdynamic ) #For asserts bt
        add_compile_definitions ( WAZUH_ASSERT_WITH_SYM )
    endif()
    add_compile_definitions ( WAZUH_DEBUG )
endif()

if(ENGINE_BUILD_BENCHMARK AND
   NOT CMAKE_BUILD_TYPE STREQUAL "Release" AND
   NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(WARNING "Building and running benchmarks in '${CMAKE_BUILD_TYPE}' will skew the results; use Release or RelWithDebInfo.")
endif()

# Ensures that we do an out of source build
MACRO(MACRO_ENSURE_OUT_OF_SOURCE_BUILD MSG)
     STRING(COMPARE EQUAL "${CMAKE_SOURCE_DIR}"
     "${CMAKE_BINARY_DIR}" insource)
     GET_FILENAME_COMPONENT(PARENTDIR ${CMAKE_SOURCE_DIR} PATH)
     STRING(COMPARE EQUAL "${CMAKE_SOURCE_DIR}"
     "${PARENTDIR}" insourcesubdir)
    IF(insource OR insourcesubdir)
        MESSAGE(FATAL_ERROR "${MSG}")
    ENDIF(insource OR insourcesubdir)
ENDMACRO(MACRO_ENSURE_OUT_OF_SOURCE_BUILD)

MACRO_ENSURE_OUT_OF_SOURCE_BUILD(
    "${CMAKE_PROJECT_NAME} requires an out of source build."
)

####################################################################################################
# Dependencies
####################################################################################################
# ---------------------------------------------------------------------------
# add_manual_imported(<alias> <include_dir> [<lib_or_dir>])
#
# <alias>        Public target name, e.g. MyLib::core
# <include_dir>  Header directory
# <lib_or_dir>   (optional)
#                • single file: /path/libfoo.a or foo.lib
#                • directory   : /path/to/libs   (all *.a / *.lib will be used)
#                • omitted     : header-only target
# ---------------------------------------------------------------------------
function(add_manual_imported alias header_dir static_lib)
  string(REPLACE "::" "_" internal "${alias}")

  if(static_lib)
    if(NOT TARGET ${internal})
      add_library(${internal} STATIC IMPORTED GLOBAL)
      set_target_properties(${internal}
        PROPERTIES
          IMPORTED_LOCATION "${static_lib}"
          INTERFACE_INCLUDE_DIRECTORIES "${header_dir}"
      )
      message(STATUS "  → Imported static library target ${internal} (from ${static_lib})")
    endif()
  else()
    if(NOT TARGET ${internal})
      add_library(${internal} INTERFACE)
      target_include_directories(${internal}
        INTERFACE
          "${header_dir}"
      )
      message(STATUS "  → Header-only interface target ${internal} (includes from ${header_dir})")
    endif()
  endif()

  # -------------------------------------------------------------------------
  # Create namespace alias
  # -------------------------------------------------------------------------
  if(NOT TARGET ${alias})
    add_library(${alias} ALIAS ${internal})
    message(STATUS "  → Alias target ${alias} -> ${internal}")
  endif()
endfunction()

# Build test
if(ENGINE_BUILD_TEST)
include(CTest)
# GTest y GMock
add_manual_imported(GTest::gtest         "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/googletest/include" "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/build/lib/libgtest.a")
add_manual_imported(GTest::gtest_main    "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/googletest/include" "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/build/lib/libgtest_main.a")
add_manual_imported(GTest::gmock         "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/googlemock/include" "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/build/lib/libgmock.a")
add_manual_imported(GTest::gmock_main    "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/googlemock/include" "${CMAKE_SOURCE_DIR}/external/googletest-1.15.0/build/lib/libgmock_main.a")

set_target_properties(GTest_gtest_main  PROPERTIES INTERFACE_LINK_LIBRARIES "GTest_gtest")
set_target_properties(GTest_gmock       PROPERTIES INTERFACE_LINK_LIBRARIES "GTest_gtest")
set_target_properties(GTest_gmock_main  PROPERTIES INTERFACE_LINK_LIBRARIES "GTest_gmock;GTest_gtest")
include(GoogleTest)
endif(ENGINE_BUILD_TEST)

####################################################################################################
# Rocksdb dynamic link
####################################################################################################
include_directories(${CMAKE_SOURCE_DIR}/external/rocksdb/include)
link_directories(${CMAKE_SOURCE_DIR}/external/rocksdb/build)
####################################################################################################
# Targets
####################################################################################################
# Build main
add_executable(main ${ENGINE_SOURCE_DIR}/main.cpp)

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/ ABSOLUTE)
endif()

message("PATH: ${CMAKE_SOURCE_DIR}")
add_manual_imported(fmt::fmt               "${CMAKE_SOURCE_DIR}/external/fmt-8.1.1/include" "${CMAKE_SOURCE_DIR}/external/fmt-8.1.1/build/libfmt.a")
add_manual_imported(spdlog::spdlog         "${CMAKE_SOURCE_DIR}/external/spdlog-1.14.1/include" "${CMAKE_SOURCE_DIR}/external/spdlog-1.14.1/build/libspdlog.a")
add_manual_imported(yaml-cpp::yaml-cpp     "${CMAKE_SOURCE_DIR}/external/yaml-cpp-0.8.0/include" "${CMAKE_SOURCE_DIR}/external/yaml-cpp-0.8.0/build/libyaml-cpp.a")
add_manual_imported(RapidJSON::RapidJSON   "${CMAKE_SOURCE_DIR}/external/rapidjson-a95e013b97ca6523f32da23f5095fcc9dd6067e5/include" "")
add_manual_imported(RxCpp::RxCpp           "${CMAKE_SOURCE_DIR}/external/RxCpp-4.1.1/Rx/v2/src/" "")
add_manual_imported(FastFloat::fast-float  "${CMAKE_SOURCE_DIR}/external/fast_float-6.1.4/include" "")
add_manual_imported(Taskflow::Taskflow     "${CMAKE_SOURCE_DIR}/external/taskflow-3.7.0" "")
add_manual_imported(unofficial-concurrentqueue::concurrentqueue "${CMAKE_SOURCE_DIR}/external/concurrentqueue-1.0.4" "")
add_manual_imported(OpenSSL::SSL           "${CMAKE_SOURCE_DIR}/external/openssl/include" "${CMAKE_SOURCE_DIR}/external/openssl/libssl.a")
add_manual_imported(OpenSSL::Crypto        "${CMAKE_SOURCE_DIR}/external/openssl/include" "${CMAKE_SOURCE_DIR}/external/openssl/libcrypto.a")
add_manual_imported(ZLIB::ZLIB             "${CMAKE_SOURCE_DIR}/external/zlib" "${CMAKE_SOURCE_DIR}/external/zlib/libz.a")
add_manual_imported(CURL::libcurl          "${CMAKE_SOURCE_DIR}/external/curl/include" "${CMAKE_SOURCE_DIR}/external/curl/lib/.libs/libcurl.a")
set_target_properties(CURL_libcurl PROPERTIES INTERFACE_LINK_LIBRARIES "ZLIB_ZLIB;OpenSSL_SSL;OpenSSL_Crypto")
add_manual_imported(maxminddb::maxminddb   "${CMAKE_SOURCE_DIR}/external/libmaxminddb-1.9.1/include" "${CMAKE_SOURCE_DIR}/external/libmaxminddb-1.9.1/build/libmaxminddb.a")
target_include_directories(maxminddb_maxminddb INTERFACE "${CMAKE_SOURCE_DIR}/external/libmaxminddb-1.9.1/build/generated")
add_manual_imported(benchmark::benchmark   "${CMAKE_SOURCE_DIR}/external/benchmark-1.8.5/include" "${CMAKE_SOURCE_DIR}/external/benchmark-1.8.5/build/src/libbenchmark.a")
add_manual_imported(benchmark::benchmark_main "${CMAKE_SOURCE_DIR}/external/benchmark-1.8.5/src" "${CMAKE_SOURCE_DIR}/external/benchmark-1.8.5/build/src/libbenchmark_main.a")
set_target_properties(benchmark_benchmark_main PROPERTIES INTERFACE_LINK_LIBRARIES "benchmark_benchmark")
add_manual_imported(pugixml::pugixml       "${CMAKE_SOURCE_DIR}/external/pugixml-1.15/src" "${CMAKE_SOURCE_DIR}/external/pugixml-1.15/build/libpugixml.a")
add_manual_imported(protobuf::libprotobuf  "${CMAKE_SOURCE_DIR}/external/protobuf-21.12/src" "${CMAKE_SOURCE_DIR}/external/protobuf-21.12/build/libprotobuf.a")
set(PROTOBUF_DIR "${CMAKE_SOURCE_DIR}/external/protobuf-21.12")
add_manual_imported(httplib::httplib       "${CMAKE_SOURCE_DIR}/external/cpp-httplib-0.16.2" "")
add_manual_imported(date::date             "${CMAKE_SOURCE_DIR}/external/date/include" "")
add_manual_imported(date::date-tz          "${CMAKE_SOURCE_DIR}/external/date/include" "${CMAKE_SOURCE_DIR}/external/date/build/libdate-tz.a")
add_manual_imported(absl::absl             "${CMAKE_SOURCE_DIR}/external/abseil-cpp-20240116.3" "${CMAKE_SOURCE_DIR}/external/abseil-cpp-20240116.3/build/build_result/lib/libabsl_all.a")
add_manual_imported(re2::re2               "${CMAKE_SOURCE_DIR}/external/re2-2024-06-01" "${CMAKE_SOURCE_DIR}/external/re2-2024-06-01/build/libre2.a")
set_target_properties(re2_re2 PROPERTIES INTERFACE_LINK_LIBRARIES "absl_absl")

add_subdirectory(${ENGINE_SOURCE_DIR}/base)
add_subdirectory(${ENGINE_SOURCE_DIR}/bk)
add_subdirectory(${ENGINE_SOURCE_DIR}/api)
add_subdirectory(${ENGINE_SOURCE_DIR}/defs)
add_subdirectory(${ENGINE_SOURCE_DIR}/schemf)
add_subdirectory(${ENGINE_SOURCE_DIR}/builder)
add_subdirectory(${ENGINE_SOURCE_DIR}/parsec)
add_subdirectory(${ENGINE_SOURCE_DIR}/hlp)
add_subdirectory(${ENGINE_SOURCE_DIR}/logpar)
add_subdirectory(${ENGINE_SOURCE_DIR}/kvdb)
add_subdirectory(${ENGINE_SOURCE_DIR}/logicexpr)
add_subdirectory(${ENGINE_SOURCE_DIR}/yml)
add_subdirectory(${ENGINE_SOURCE_DIR}/store)
add_subdirectory(${ENGINE_SOURCE_DIR}/router)
add_subdirectory(${ENGINE_SOURCE_DIR}/conf)
add_subdirectory(${ENGINE_SOURCE_DIR}/proto)
# TODO: Until the indexer connector is unified with the rest of wazuh-manager
# add_subdirectory(${ENGINE_SOURCE_DIR}/metrics)
add_subdirectory(${ENGINE_SOURCE_DIR}/geo)
add_subdirectory(${ENGINE_SOURCE_DIR}/queue)
add_subdirectory(${ENGINE_SOURCE_DIR}/httpsrv)
add_subdirectory(${ENGINE_SOURCE_DIR}/udgramsrv)
add_subdirectory(${ENGINE_SOURCE_DIR}/archiver)

target_link_libraries(main
    base
    conf
    yml
    defs
    builder
    #bk::taskf
    bk::rx
    router::router
    store
    store::fileDriver
    api
    kvdb
    eMessages
    # metrics # TODO: Comment until indexerconnector is unified with the old one
    geo
    schemf
    geo::igeo
    # indexerconnector # TODO: Comment until indexerconnector is unified with the old one
    httpsrv
    udgramsrv::udgramsrv
    api::event
    queue
    archiver
)

# If ASAN, UBSAN or any other sanitizers are enabled do not link with static libraries
if(NOT CMAKE_CXX_FLAGS MATCHES "-fsanitize=.*")
    target_link_libraries(main -static-libgcc -static-libstdc++)
endif()


# Create a custom test target
function(get_all_targets _result _dir)
    get_property(_subdirs DIRECTORY "${_dir}" PROPERTY SUBDIRECTORIES)
    foreach(_subdir IN LISTS _subdirs)
        get_all_targets(${_result} "${_subdir}")
    endforeach()

    get_directory_property(_sub_targets DIRECTORY "${_dir}" BUILDSYSTEM_TARGETS)
    set(${_result} ${${_result}} ${_sub_targets} PARENT_SCOPE)
endfunction()

# Create a empty list to store all targets
set(ALL_TARGETS)
set(test_targets_to_build)

# Get all targets
get_all_targets(ALL_TARGETS ${CMAKE_CURRENT_SOURCE_DIR})

# Filter test targets and add them to the test_targets_to_build list
foreach(target ${ALL_TARGETS})
    # print all targets
    # Test end with _test _ctest or _utest
    if(${target} MATCHES "_test$" OR ${target} MATCHES "_ctest$" OR ${target} MATCHES "_utest$")
        list(APPEND test_targets_to_build ${target})
        message(STATUS "Test target: ${target}")
    endif()
endforeach()

add_custom_target(all_tests DEPENDS ${test_targets_to_build})


# Check if coverage report is enabled
if(DEFINED ENABLE_COVERAGE_REPORT AND ENABLE_COVERAGE_REPORT)
    message(STATUS "Coverage report generation is enabled.")

    # Add coverage flags
    add_custom_target(coverage
        COMMAND lcov --capture --directory ${CMAKE_BINARY_DIR} --output-file ${CMAKE_BINARY_DIR}/coverage.info --ignore-errors mismatch
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '/usr/*' '*/test/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info --ignore-errors mismatch
        COMMAND genhtml ${CMAKE_BINARY_DIR}/coverage.info --output-directory ${CMAKE_BINARY_DIR}/coverage_report
        COMMENT "Generating coverage report in ${CMAKE_BINARY_DIR}/coverage_report"
    )
else()
    message(STATUS "Coverage report generation is not enabled.")
endif()


# Generate doc
if(ENGINE_BUILD_DOCUMENTATION)
find_package(Doxygen)
if (DOXYGEN_FOUND)
    # set input and output files
    set(DOXYGEN_IN ${ENGINE_DOC_DIR}/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile) # Need to change this once install is configured

    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

    # note the option ALL which allows to build the docs together with the application
    add_custom_target( doc_doxygen
      COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen"
    )

else (DOXYGEN_FOUND)
  message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)
endif(ENGINE_BUILD_DOCUMENTATION)

# Custom clean targets
add_custom_target( clean_insource
    COMMAND rm -f "${CMAKE_SOURCE_DIR}/CMakeCache.txt"
    COMMAND rm -rf "${CMAKE_SOURCE_DIR}/CMakeFiles"
    COMMAND rm -f "${CMAKE_SOURCE_DIR}/cmake_install.cmake"
    COMMAND rm -f "${CMAKE_SOURCE_DIR}/Makefile"
    ERROR_QUIET )

add_custom_target( clean_build
    COMMAND rm -rf "${CMAKE_SOURCE_DIR}/build/*"
    ERROR_QUIET )
