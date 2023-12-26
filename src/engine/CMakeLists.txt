# Minimum 3.14 required by googletest discover tests
# Todo find wich component is not working properly until 3.24 version
cmake_minimum_required(VERSION 3.24 FATAL_ERROR)

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
set(ENGINE_TEST_DIR ${PROJECT_SOURCE_DIR}/test)
set(ENGINE_BENCHMARK_DIR ${PROJECT_SOURCE_DIR}/benchmark)
set(ENGINE_DOC_DIR ${PROJECT_SOURCE_DIR}/docs)

# Options
option(ENGINE_BUILD_TEST "Generate tests" ON)
option(ENGINE_BUILD_ASAN "Enable address sanitizer" OFF)
option(ENGINE_BUILD_TSAN "Enable thread sanitizer" OFF)
option(ENGINE_BUILD_UBSAN "Enable undefined behavior sanitizer" OFF)
option(ENGINE_BUILD_BENCHMARK "Generate benchmarks" ON)
option(ENGINE_BUILD_DOCUMENTATION "Generate doxygen documentation" ON)
option(ENGINE_BUILD_COVERAGE "Enables the coverage report" OFF)
option(ENGINE_PROFILE_BUILD "Enables profiling through Tracy" OFF)
option(ENGINE_PROFILE_MEMORY "Enables memory profiling in Tracy" OFF)
option(ENGINE_ASSERT_WITH_SYMBOLS "Exports exe symbols to have asserts with full symbolicated functions" ON)

# TODO put this in a better place together with other global options like warnings
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(ENGINE_ASSERT_WITH_SYMBOLS)
        add_link_options ( -rdynamic ) #For asserts bt
        add_compile_definitions ( WAZUH_ASSERT_WITH_SYM )
    endif()
    add_compile_definitions ( WAZUH_DEBUG )
endif()

# Add the Sanitizers
if (ENGINE_BUILD_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address -fno-omit-frame-pointer)
endif()

if (ENGINE_BUILD_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread -fno-omit-frame-pointer)
endif()

if (ENGINE_BUILD_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined -fno-omit-frame-pointer)
endif()

# Add the coverage report
if (ENGINE_BUILD_COVERAGE)
    add_compile_options(-g -fprofile-arcs -ftest-coverage -lgcov --coverage)
    add_link_options(-lgcov --coverage)
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
# CPM DOWNLOAD
####################################################################################################

set(CPM_DOWNLOAD_VERSION 0.35.6)

if(CPM_SOURCE_CACHE)
  set(CPM_DOWNLOAD_LOCATION "${CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
elseif(DEFINED ENV{CPM_SOURCE_CACHE})
  set(CPM_DOWNLOAD_LOCATION "$ENV{CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
else()
  set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
endif()

if(NOT (EXISTS ${CPM_DOWNLOAD_LOCATION}))
  message(STATUS "Downloading CPM.cmake to ${CPM_DOWNLOAD_LOCATION}")
  file(DOWNLOAD
       https://github.com/TheLartians/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake
       ${CPM_DOWNLOAD_LOCATION}
  )
endif()

include(${CPM_DOWNLOAD_LOCATION})

####################################################################################################
# Dependencies
####################################################################################################
include(cmake/CPM.cmake)

# Concurrent Queue
CPMAddPackage(
  NAME CameronQueue
  GITHUB_REPOSITORY cameron314/concurrentqueue
  GIT_TAG v1.0.3
  VERSION 1.0.3
  EXCLUDE_FROM_ALL YES
)

CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
  EXCLUDE_FROM_ALL YES
)

CPMAddPackage(
  NAME CLI11
  GITHUB_REPOSITORY CLIUtils/CLI11
  GIT_TAG v2.2.0
  VERSION 2.2.0
  DOWNLOAD_ONLY YES
)

# Build test
if(ENGINE_BUILD_TEST)
enable_testing()
CPMAddPackage(
    NAME googletest
    GITHUB_REPOSITORY google/googletest
    GIT_TAG release-1.11.0
    VERSION 1.11.0
    OPTIONS
    "INSTALL_GTEST OFF"
    EXCLUDE_FROM_ALL YES
)
include(GoogleTest)
endif(ENGINE_BUILD_TEST)

####################################################################################################
# Targets
####################################################################################################
# Build main
add_executable(main ${ENGINE_SOURCE_DIR}/main.cpp)

target_include_directories(main
    PRIVATE
    ${CLI11_SOURCE_DIR}/include
)

add_subdirectory(${ENGINE_SOURCE_DIR}/base)
add_subdirectory(${ENGINE_SOURCE_DIR}/sockiface)
add_subdirectory(${ENGINE_SOURCE_DIR}/bk)
add_subdirectory(${ENGINE_SOURCE_DIR}/rbac)
add_subdirectory(${ENGINE_SOURCE_DIR}/api)
add_subdirectory(${ENGINE_SOURCE_DIR}/defs)
add_subdirectory(${ENGINE_SOURCE_DIR}/schemf)
add_subdirectory(${ENGINE_SOURCE_DIR}/schemval)
add_subdirectory(${ENGINE_SOURCE_DIR}/builder)
add_subdirectory(${ENGINE_SOURCE_DIR}/parsec)
add_subdirectory(${ENGINE_SOURCE_DIR}/hlp)
add_subdirectory(${ENGINE_SOURCE_DIR}/logpar)
add_subdirectory(${ENGINE_SOURCE_DIR}/kvdb)
add_subdirectory(${ENGINE_SOURCE_DIR}/logicexpr)
add_subdirectory(${ENGINE_SOURCE_DIR}/server)
add_subdirectory(${ENGINE_SOURCE_DIR}/json)
add_subdirectory(${ENGINE_SOURCE_DIR}/yml)
add_subdirectory(${ENGINE_SOURCE_DIR}/wdb)
add_subdirectory(${ENGINE_SOURCE_DIR}/cmds)
add_subdirectory(${ENGINE_SOURCE_DIR}/store)
add_subdirectory(${ENGINE_SOURCE_DIR}/router)
add_subdirectory(${ENGINE_SOURCE_DIR}/conf)
add_subdirectory(${ENGINE_SOURCE_DIR}/proto)
add_subdirectory(${ENGINE_SOURCE_DIR}/metrics)
add_subdirectory(${ENGINE_SOURCE_DIR}/queue)


#TODO isolate rxcpp
target_link_libraries(main base cmds api)

# Build test
if(ENGINE_BUILD_TEST)
add_subdirectory(${ENGINE_TEST_DIR})
endif(ENGINE_BUILD_TEST)

# Build benchmark
if(ENGINE_BUILD_BENCHMARK)
add_subdirectory(${ENGINE_BENCHMARK_DIR})
endif(ENGINE_BUILD_BENCHMARK)

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
