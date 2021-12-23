# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

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
option(ENGINE_BUILD_BENCHMARK "Generate benchmarks" ON)
option(ENGINE_BUILD_DOCUMENTATION "Generate doxygen documentation" ON)
option(ENGINE_FORMAT_SOURCES "Format sources using astyle on building" ON)

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

# Format sources and headers as per guidelines using astyle, benchmarks and tests sources excluded
if(ENGINE_FORMAT_SOURCES)
find_program(ASTYLE_EXECUTABLE astyle DOC "A tool to format the code")
if(ASTYLE_EXECUTABLE)
add_custom_target(format_sources
  COMMAND ${ASTYLE_EXECUTABLE} --style=allman --formatted --indent=spaces=4 --indent-classes --indent-switches --indent-cases --indent-namespaces --indent-col1-comments --max-instatement-indent=120 --break-blocks --pad-oper --pad-header --pad-comma --align-pointer=type --align-reference=type --convert-tabs --max-code-length=200 --preserve-date --suffix=none --quiet --recursive ${ENGINE_SOURCE_DIR}/*.cpp,*.hpp
)
add_custom_target(format_tests
  COMMAND ${ASTYLE_EXECUTABLE} --style=allman --formatted --indent=spaces=4 --indent-classes --indent-switches --indent-cases --indent-namespaces --indent-col1-comments --max-instatement-indent=120 --break-blocks --pad-oper --pad-header --pad-comma --align-pointer=type --align-reference=type --convert-tabs --max-code-length=200 --preserve-date --suffix=none --quiet --recursive ${ENGINE_TEST_DIR}/*.cpp,*.hpp
)
add_custom_target(format_benchmarks
  COMMAND ${ASTYLE_EXECUTABLE} --style=allman --formatted --indent=spaces=4 --indent-classes --indent-switches --indent-cases --indent-namespaces --indent-col1-comments --max-instatement-indent=120 --break-blocks --pad-oper --pad-header --pad-comma --align-pointer=type --align-reference=type --convert-tabs --max-code-length=200 --preserve-date --suffix=none --quiet --recursive ${ENGINE_BENCHMARK_DIR}/*.cpp,*.hpp
)
else()
message("astyle executable not found, sources won't be formatted" WARNING)
endif(ASTYLE_EXECUTABLE)
endif(ENGINE_FORMAT_SOURCES)

####################################################################################################
# Dependencies
####################################################################################################
include(cmake/CPM.cmake)

# # boost
# CPMAddPackage(
#   NAME Boost
#   VERSION 1.78.0
#   GITHUB_REPOSITORY "boostorg/boost"
#   GIT_TAG "boost-1.78.0"
# )
# find_package(Boost
#     1.78.0
#     COMPONENTS asio coroutine regex system)
# if(Boost_FOUND)
#     include_directories(${Boost_INCLUDE_DIRS})
#     list(APPEND EXTERNAL_DEPS "pthread" "Boost::asio" "Boost::coroutine" "Boost::regex" "Boost::system" "Boost:boost")
#     set(CMAKE_CXX_FLAGS -fcoroutines)
#     # set(CMAKE_EXE_LINKER_FLAGS -lboost_coroutine -lboost_system)
# endif(Boost_FOUND)

# nlohmann json
CPMAddPackage(
  NAME json
  GITHUB_REPOSITORY nlohmann/json
  GIT_TAG v3.10.4
  VERSION 3.10.4
  OPTIONS
      "JSON_BuildTests OFF"
      "JSON_Install OFF"
)
list(APPEND EXTERNAL_DEPS "nlohmann_json::nlohmann_json")

# google logging
CPMAddPackage(
  NAME glog
  GITHUB_REPOSITORY google/glog
  GIT_TAG v0.5.0
  VERSION 0.5.0
  OPTIONS
      "WITH_GTEST OFF"
      "BUILD_SHARED_LIBS OFF"
      "WITH_GFLAGS OFF"
      "WITH_UNWIND OFF"
)
list(APPEND EXTERNAL_DEPS "glog::glog")
####################################################################################################

# Build main
set(SOURCE_FILES "${ENGINE_SOURCE_DIR}/main.cpp")

add_executable(main ${SOURCE_FILES})

# Build catalog
add_subdirectory(${ENGINE_SOURCE_DIR}/catalog)

target_link_libraries(main "-static" ${EXTERNAL_DEPS})

# Build test
if(ENGINE_BUILD_TEST)
enable_testing()
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
    add_custom_target( doc_doxygen ALL
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
