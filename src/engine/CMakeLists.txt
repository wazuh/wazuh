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
option(ENGINE_BUILD_TEST "Generate tests" OFF)
option(ENGINE_BUILD_BENCHMARK "Generate benchmarks" OFF)
option(ENGINE_ENABLE_ASAN "Enable AddressSanitizer for all targets" OFF)
option(ENGINE_BUILD_DOCUMENTATION "Generate doxygen documentation" OFF)
option(ENGINE_ASSERT_WITH_SYMBOLS "Exports exe symbols to have asserts with full symbolicated functions" ON)
option(ENGINE_GENERATE_PROTO "Generate protobuf code" OFF)


if(WAZUH_ENGINE_TEST)
    set(ENGINE_BUILD_TEST ON CACHE BOOL "Generate tests" FORCE)
    set(ENGINE_BUILD_BENCHMARK ON CACHE BOOL "Generate benchmarks" FORCE)
elseif(UNIT_TEST)
  set(ENGINE_BUILD_TEST ON CACHE BOOL "Generate tests" FORCE)
  set(ENGINE_ENABLE_ASAN ON CACHE BOOL "Enable AddressSanitizer for all targets" FORCE)
endif()


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

if(ENGINE_ENABLE_ASAN)
  message(STATUS "Building engine with AddressSanitizer")
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address -fno-omit-frame-pointer)
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
# register_external_library(<alias> <include_dir> [<lib_or_dir>])
#
# <alias>        Public target name, e.g. MyLib::core
# <include_dir>  Header directory
# <lib_or_dir>   (optional)
#                • single file: /path/libfoo.a or foo.lib
#                • directory   : /path/to/libs   (all *.a / *.lib will be used)
# ---------------------------------------------------------------------------
function(register_external_library alias header_dir static_lib)
  string(REPLACE "::" "_" internal "${alias}")

  if(static_lib AND IS_DIRECTORY "${static_lib}")
    if(NOT TARGET ${internal})
      add_library(${internal} INTERFACE)
      target_include_directories(${internal}
        INTERFACE
          "${header_dir}"
      )

      # Recursive search .a y .so
      file(GLOB_RECURSE _a_libs   "${static_lib}/*.a")
      file(GLOB_RECURSE _so_libs  "${static_lib}/*.so")
      set(_all_libs ${_a_libs} ${_so_libs})

      if(_all_libs)
        target_link_libraries(${internal}
          INTERFACE
            $<$<LINK_LANGUAGE:CXX>:-Wl,--start-group>
            ${_all_libs}
            $<$<LINK_LANGUAGE:CXX>:-Wl,--end-group>
        )
        message(STATUS "  → Imported libs from dir (recursive) ${static_lib}: ${_all_libs}")
      else()
        message(WARNING "  → No .a/.so found recursively in ${static_lib}")
      endif()
    endif()

  elseif(static_lib)
    if(NOT TARGET ${internal})
      add_library(${internal} STATIC IMPORTED GLOBAL)
      set_target_properties(${internal}
        PROPERTIES
          IMPORTED_LOCATION             "${static_lib}"
          INTERFACE_INCLUDE_DIRECTORIES "${header_dir}"
      )
      message(STATUS "  → Imported static library ${internal} (from ${static_lib})")
    endif()

  else()
    if(NOT TARGET ${internal})
      add_library(${internal} INTERFACE)
      target_include_directories(${internal}
        INTERFACE
          "${header_dir}"
      )
      message(STATUS "  → Header-only interface target ${internal}")
    endif()
  endif()

  if(NOT TARGET ${alias})
    add_library(${alias} ALIAS ${internal})
    message(STATUS "  → Alias target ${alias} -> ${internal}")
  endif()
endfunction()

# Build test
if(ENGINE_BUILD_TEST)
include(CTest)
# GTest y GMock
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  register_external_library(GTest::gtest         "${CMAKE_SOURCE_DIR}/external/googletest/googletest/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgtestd.a")
  register_external_library(GTest::gtest_main    "${CMAKE_SOURCE_DIR}/external/googletest/googletest/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgtest_maind.a")
  register_external_library(GTest::gmock         "${CMAKE_SOURCE_DIR}/external/googletest/googlemock/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgmockd.a")
  register_external_library(GTest::gmock_main    "${CMAKE_SOURCE_DIR}/external/googletest/googlemock/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgmock_maind.a")
else()
  register_external_library(GTest::gtest         "${CMAKE_SOURCE_DIR}/external/googletest/googletest/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgtest.a")
  register_external_library(GTest::gtest_main    "${CMAKE_SOURCE_DIR}/external/googletest/googletest/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgtest_main.a")
  register_external_library(GTest::gmock         "${CMAKE_SOURCE_DIR}/external/googletest/googlemock/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgmock.a")
  register_external_library(GTest::gmock_main    "${CMAKE_SOURCE_DIR}/external/googletest/googlemock/include" "${CMAKE_SOURCE_DIR}/external/googletest/build/lib/libgmock_main.a")
endif()

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

# Build main
add_executable(main ${ENGINE_SOURCE_DIR}/main.cpp)

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/ ABSOLUTE)
endif()

find_package(Threads QUIET)
if (NOT Threads_FOUND)
  message(WARNING "Threads not found by CMake; forcing -lpthread fallback")
  set(CMAKE_THREAD_LIBS_INIT "-lpthread"      CACHE STRING "" FORCE)
  set(Threads_FOUND            TRUE             CACHE BOOL   "" FORCE)
endif()

message("PATH: ${CMAKE_SOURCE_DIR}")
register_external_library(fmt::fmt               "${CMAKE_SOURCE_DIR}/external/fmt/include" "${CMAKE_SOURCE_DIR}/external/fmt/build/libfmt.a")
register_external_library(spdlog::spdlog         "${CMAKE_SOURCE_DIR}/external/spdlog/include" "${CMAKE_SOURCE_DIR}/external/spdlog/build/libspdlog.a")
register_external_library(yaml-cpp::yaml-cpp     "${CMAKE_SOURCE_DIR}/external/yaml-cpp/include" "${CMAKE_SOURCE_DIR}/external/yaml-cpp/build/libyaml-cpp.a")
register_external_library(RapidJSON::RapidJSON   "${CMAKE_SOURCE_DIR}/external/rapidjson/include" "")
register_external_library(RxCpp::RxCpp           "${CMAKE_SOURCE_DIR}/external/RxCpp/Rx/v2/src/" "")
register_external_library(FastFloat::fast-float  "${CMAKE_SOURCE_DIR}/external/fast_float/include" "")
register_external_library(Taskflow::Taskflow     "${CMAKE_SOURCE_DIR}/external/taskflow" "")
register_external_library(unofficial-concurrentqueue::concurrentqueue "${CMAKE_SOURCE_DIR}/external/concurrentqueue" "")
register_external_library(OpenSSL::SSL           "${CMAKE_SOURCE_DIR}/external/openssl/include" "${CMAKE_SOURCE_DIR}/external/openssl/libssl.a")
register_external_library(OpenSSL::Crypto        "${CMAKE_SOURCE_DIR}/external/openssl/include" "${CMAKE_SOURCE_DIR}/external/openssl/libcrypto.a")
register_external_library(ZLIB::ZLIB             "${CMAKE_SOURCE_DIR}/external/zlib" "${CMAKE_SOURCE_DIR}/external/zlib/libz.a")
register_external_library(CURL::libcurl          "${CMAKE_SOURCE_DIR}/external/curl/include" "${CMAKE_SOURCE_DIR}/external/curl/lib/.libs/libcurl.a")
set_target_properties(CURL_libcurl PROPERTIES INTERFACE_LINK_LIBRARIES "ZLIB_ZLIB;OpenSSL_SSL;OpenSSL_Crypto")
register_external_library(maxminddb::maxminddb   "${CMAKE_SOURCE_DIR}/external/libmaxminddb/include" "${CMAKE_SOURCE_DIR}/external/libmaxminddb/build/libmaxminddb.a")
target_include_directories(maxminddb_maxminddb INTERFACE "${CMAKE_SOURCE_DIR}/external/libmaxminddb/build/generated")
register_external_library(benchmark::benchmark   "${CMAKE_SOURCE_DIR}/external/benchmark/include" "${CMAKE_SOURCE_DIR}/external/benchmark/build/src/libbenchmark.a")
register_external_library(benchmark::benchmark_main "${CMAKE_SOURCE_DIR}/external/benchmark/src" "${CMAKE_SOURCE_DIR}/external/benchmark/build/src/libbenchmark_main.a")
set_target_properties(benchmark_benchmark_main PROPERTIES INTERFACE_LINK_LIBRARIES "benchmark_benchmark")
register_external_library(pugixml::pugixml       "${CMAKE_SOURCE_DIR}/external/pugixml/src" "${CMAKE_SOURCE_DIR}/external/pugixml/build/libpugixml.a")
register_external_library(protobuf::libprotobuf  "${CMAKE_SOURCE_DIR}/external/protobuf/src" "${CMAKE_SOURCE_DIR}/external/protobuf/build/libprotobuf.a")
set(PROTOBUF_DIR "${CMAKE_SOURCE_DIR}/external/protobuf")
register_external_library(date::date             "${CMAKE_SOURCE_DIR}/external/date/include" "")
register_external_library(date::date-tz          "${CMAKE_SOURCE_DIR}/external/date/include" "${CMAKE_SOURCE_DIR}/external/date/build/libdate-tz.a")
register_external_library(absl::absl             "${CMAKE_SOURCE_DIR}/external/abseil-cpp" "${CMAKE_SOURCE_DIR}/external/abseil-cpp/build/build_result")
target_link_libraries(absl_absl INTERFACE Threads::Threads ${CMAKE_DL_LIBS})
register_external_library(re2::re2               "${CMAKE_SOURCE_DIR}/external/re2" "${CMAKE_SOURCE_DIR}/external/re2/build/libre2.a")
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
