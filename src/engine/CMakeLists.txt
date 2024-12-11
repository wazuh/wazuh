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
set(ENGINE_BENCHMARK_DIR ${PROJECT_SOURCE_DIR}/benchmark)
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

if(DEFINED VCPKG_TARGET_TRIPLET)
    message(STATUS "Using VCPKG triplet: ${VCPKG_TARGET_TRIPLET}")
else()
    message(WARNING "VCPKG_TARGET_TRIPLET is not defined. Make sure you are using the vcpkg toolchain.")
    FATAL_ERROR("VCPKG_TARGET_TRIPLET is not defined.")
endif()

####################################################################################################
# Temporary IANA Time Zone Database fixed
####################################################################################################
function(configure_tzdb)

    set(TZDB_VERSION "2024a")
    set(TZDB_URL "https://ftp.iana.org/tz/releases/tzdb-${TZDB_VERSION}.tar.lz")
    set(TZDB_DIR "${CMAKE_BINARY_DIR}/tzdb")
    set(TZDB_TAR "${CMAKE_BINARY_DIR}/tzcode${TZDB_VERSION}.tar.lz")
    set(TZDB_HLP_TEST_DIR "${CMAKE_BINARY_DIR}/source/hlp/data")

    find_program(WGET wget)
    find_program(TAR tar)
    find_program(LZIP lzip)

    if(NOT WGET)
        message(FATAL_ERROR "wget is required but not found. Please install wget.")
    endif()

    if(NOT TAR)
        message(FATAL_ERROR "tar is required but not found. Please install tar.")
    endif()

    if(NOT LZIP)
        message(FATAL_ERROR "lzip is required but not found. Please install lzip.")
    endif()

    # Download tzdb
    if(NOT EXISTS ${TZDB_TAR})
        message(STATUS "Downloading tzdb version ${TZDB_VERSION} from ${TZDB_URL}")
        execute_process(
            COMMAND ${WGET} ${TZDB_URL} -O ${TZDB_TAR}
            RESULT_VARIABLE DOWNLOAD_RESULT
        )
        if(NOT DOWNLOAD_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to download tzdb from ${TZDB_URL}")
        endif()
    endif()

    # Check if tzdb directory exists if not extract it
    if(NOT EXISTS ${TZDB_DIR})
        message(STATUS "Creating directory ${TZDB_DIR} for extraction")
        file(MAKE_DIRECTORY ${TZDB_DIR})  # Crear el directorio de destino

        message(STATUS "Extracting tzdb version ${TZDB_VERSION} into ${TZDB_DIR}")
        execute_process(
            COMMAND ${TAR} --lzip --strip-components=1 -xvf ${TZDB_TAR} -C ${TZDB_DIR}
            RESULT_VARIABLE EXTRACT_RESULT
        )
        if(NOT EXTRACT_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to extract tzdb file ${TZDB_TAR}")
        endif()
    endif()

    file(MAKE_DIRECTORY ${TZDB_HLP_TEST_DIR})
    file(COPY ${TZDB_DIR} DESTINATION ${TZDB_HLP_TEST_DIR} FILES_MATCHING PATTERN "*")


endfunction()
# Temporaty fix for IANA Time Zone Database
configure_tzdb()


####################################################################################################
# Dependencies
####################################################################################################
function(action package_name target_name)
    if (${package_name}_FOUND)
        if (NOT TARGET ${target_name})
            add_library(${target_name} INTERFACE IMPORTED)
            set_target_properties(${target_name} PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${${package_name}_INCLUDE_DIRS}")
            message(STATUS "Created imported target ${target_name}")
        else()
            message(STATUS "Target ${target_name} already exists")
        endif()
    else()
        message(FATAL_ERROR "${package_name} not found!")
    endif()
endfunction()

function(find_and_create_imported_target package_name target_name)
    find_package(${package_name} CONFIG REQUIRED)
    action(${package_name} ${target_name})
endfunction()

function(find_and_create_imported_target_ex package_name target_name)
    find_package(${package_name} REQUIRED)
    action(${package_name} ${target_name})
endfunction()

# Build test
if(ENGINE_BUILD_TEST)
include(CTest)
find_and_create_imported_target("GTest" "GTest::gtest")
find_and_create_imported_target("GTest" "GTest::gtest_main")
find_and_create_imported_target("GTest" "GTest::gmock")
find_and_create_imported_target("GTest" "GTest::gmock_main")
include(GoogleTest)
endif(ENGINE_BUILD_TEST)

find_and_create_imported_target("RapidJSON" "RapidJSON::RapidJSON")
find_and_create_imported_target("rxcpp" "RxCpp::RxCpp")
# yaml-cpp::yaml-cpp vs yaml-cpp #FIXME 70 stars on github
find_and_create_imported_target("yaml-cpp" "yaml-cpp::yaml-cpp")
find_and_create_imported_target("spdlog" "spdlog::spdlog")
find_and_create_imported_target("FastFloat" "FastFloat::fast-float")
find_and_create_imported_target("fmt" "fmt::fmt-header-only")
find_and_create_imported_target("RocksDB" "RocksDB::rocksdb")
find_and_create_imported_target("Taskflow" "Taskflow::Taskflow")
find_and_create_imported_target("unofficial-concurrentqueue" "unofficial-concurrentqueue::concurrentqueue")
find_and_create_imported_target("re2" "re2::re2")
find_and_create_imported_target("CURL" "CURL::libcurl")
find_and_create_imported_target("maxminddb" "maxminddb::maxminddb")
find_and_create_imported_target("benchmark" "benchmark::benchmark")
find_and_create_imported_target("pugixml" "pugixml::pugixml")

find_and_create_imported_target("libuv" "libuv::libuv")
find_and_create_imported_target("uvw" "uvw::uvw")

find_and_create_imported_target("opentelemetry-cpp" "opentelemetry-cpp::api")
find_and_create_imported_target("opentelemetry-cpp" "opentelemetry-cpp::sdk")
find_and_create_imported_target("opentelemetry-cpp" "opentelemetry-cpp::logs")
find_and_create_imported_target("opentelemetry-cpp" "opentelemetry-cpp::metrics")

find_and_create_imported_target("Protobuf" "protobuf::libprotobuf")
find_and_create_imported_target("flatbuffers" "flatbuffers::flatbuffers")
find_and_create_imported_target("httplib" "httplib::httplib")

find_and_create_imported_target("date" "date::date")
find_and_create_imported_target("date" "date::date-tz")

find_and_create_imported_target("liblzma" "liblzma::liblzma")
find_and_create_imported_target_ex("LibArchive" "LibArchive::LibArchive")

####################################################################################################
# Targets
####################################################################################################
# Build main
add_executable(main ${ENGINE_SOURCE_DIR}/main.cpp)

add_subdirectory(${ENGINE_SOURCE_DIR}/feedmanager)
add_subdirectory(${ENGINE_SOURCE_DIR}/vdscanner)
add_subdirectory(${ENGINE_SOURCE_DIR}/wazuh-http-request)
add_subdirectory(${ENGINE_SOURCE_DIR}/indexerconnector)
add_subdirectory(${ENGINE_SOURCE_DIR}/base)
add_subdirectory(${ENGINE_SOURCE_DIR}/sockiface)
add_subdirectory(${ENGINE_SOURCE_DIR}/bk)
add_subdirectory(${ENGINE_SOURCE_DIR}/rbac)
add_subdirectory(${ENGINE_SOURCE_DIR}/api)
add_subdirectory(${ENGINE_SOURCE_DIR}/defs)
add_subdirectory(${ENGINE_SOURCE_DIR}/schemf)
add_subdirectory(${ENGINE_SOURCE_DIR}/builder)
add_subdirectory(${ENGINE_SOURCE_DIR}/parsec)
add_subdirectory(${ENGINE_SOURCE_DIR}/hlp)
add_subdirectory(${ENGINE_SOURCE_DIR}/logpar)
add_subdirectory(${ENGINE_SOURCE_DIR}/kvdb)
add_subdirectory(${ENGINE_SOURCE_DIR}/logicexpr)
add_subdirectory(${ENGINE_SOURCE_DIR}/server)
add_subdirectory(${ENGINE_SOURCE_DIR}/yml)
add_subdirectory(${ENGINE_SOURCE_DIR}/wdb)
add_subdirectory(${ENGINE_SOURCE_DIR}/store)
add_subdirectory(${ENGINE_SOURCE_DIR}/router)
add_subdirectory(${ENGINE_SOURCE_DIR}/conf)
add_subdirectory(${ENGINE_SOURCE_DIR}/proto)
add_subdirectory(${ENGINE_SOURCE_DIR}/metrics)
add_subdirectory(${ENGINE_SOURCE_DIR}/geo)
add_subdirectory(${ENGINE_SOURCE_DIR}/queue)
add_subdirectory(${ENGINE_SOURCE_DIR}/apiserver)
add_subdirectory(${ENGINE_SOURCE_DIR}/fs)
add_subdirectory(${ENGINE_SOURCE_DIR}/httpsrv)

target_link_libraries(main
    base
    conf
    yml
    defs
    builder
    #bk::taskf
    bk::rx
    server
    router::router
    store
    api
    libuv::uv_a
    kvdb
    eMessages
    metrics
    geo
    schemf
    wdb
    sockiface
    rbac
    geo::igeo
    vdscanner
    apiserver
    indexerconnector
    httpsrv
)

# If ASAN, UBSAN or any other sanitizers are enabled do not link with static libraries
if(NOT CMAKE_CXX_FLAGS MATCHES "-fsanitize=.*")
    target_link_libraries(main -static-libgcc -static-libstdc++)
endif()

# Build benchmark
if(ENGINE_BUILD_BENCHMARK)
add_subdirectory(${ENGINE_BENCHMARK_DIR})
endif(ENGINE_BUILD_BENCHMARK)

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
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '/usr/*' '*/test/*' '*/build/vcpkg_installed/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info --ignore-errors mismatch
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
