cmake_minimum_required(VERSION 3.12.4)

project(Wazuh LANGUAGES CXX)

# define the C++ standard and global compilation options
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread)

# define directory variables
get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/shared_modules ABSOLUTE)
get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/ ABSOLUTE)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Using "Release" as default build type
set(DEFAULT_BUILD_TYPE Release)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE ${DEFAULT_BUILD_TYPE})
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
else()
  message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
endif()

# Target to compile all the tests of the subdirectories
set(ALL_UNIT_TEST_TARGET all_unit_test)
add_custom_target(${ALL_UNIT_TEST_TARGET})
enable_testing()

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

# Address sanitizer only in Debug mode
if(FSANITIZE)
  string(APPEND CMAKE_CXX_FLAGS_DEBUG " -fsanitize=address,leak,undefined")

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -fprofile-arcs ")
  else()
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -lgcov ")
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
endif(FSANITIZE)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options("$<$<CONFIG:RELEASE>:-O3>")
else()
  add_compile_options("$<$<CONFIG:RELEASE>:-O3;-s>")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

# Include directories (helpers)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/utils)

# Include directories (global defs)
include_directories(${SRC_FOLDER}/headers/)

# Include directories (external)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/procps/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/libplist/bin/include/)
include_directories(${SRC_FOLDER}/external/libdb/build_unix/)

# Link directories (external)
link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/procps/)
link_directories(${SRC_FOLDER}/external/bzip2/)
link_directories(${SRC_FOLDER}/external/libplist/bin/lib/)
link_directories(${SRC_FOLDER}/external/libdb/build_unix/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/)

# Compile GTest/GMock if the tests are on
if(UNIT_TEST)
  add_subdirectory(${SRC_FOLDER}/external/googletest)
  include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
  include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
  link_directories(${SRC_FOLDER}/external/googletest/lib/)
endif(UNIT_TEST)

add_subdirectory(data_provider)
add_subdirectory(shared_modules)
add_subdirectory(wazuh_modules/syscollector)
