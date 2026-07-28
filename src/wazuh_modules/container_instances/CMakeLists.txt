cmake_minimum_required(VERSION 3.12.4)

project(container_instances)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(include)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/libyaml/include/)
include_directories(${SRC_FOLDER}/external/curl/include/)
include_directories(${SRC_FOLDER}/shared/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/filesystem/include/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include/)

link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/libyaml/src/.libs/)
link_directories(${SRC_FOLDER}/external/curl/lib/.libs/)
link_directories(${SRC_FOLDER}/external/zlib/)
link_directories(${CMAKE_BINARY_DIR}/lib)

find_library(
  FILESYSTEM_WRAPPER_LIB FilesystemWrapper
  HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib ${CMAKE_BINARY_DIR}/lib
  NO_DEFAULT_PATH)
find_library(
  FILE_IO_LIB FileIO
  HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib ${CMAKE_BINARY_DIR}/lib
  NO_DEFAULT_PATH)
if(NOT FILESYSTEM_WRAPPER_LIB)
  set(FILESYSTEM_WRAPPER_LIB FilesystemWrapper)
endif()
if(NOT FILE_IO_LIB)
  set(FILE_IO_LIB FileIO)
endif()

file(GLOB CONTAINER_INSTANCES_SRC "src/*.cpp" "ci_impl/src/*/*.cpp")

add_library(container_instances SHARED ${CONTAINER_INSTANCES_SRC})

target_link_libraries(
  container_instances
  PRIVATE ${FILESYSTEM_WRAPPER_LIB}
          ${FILE_IO_LIB}
          curl
          yaml
          ssl
          crypto
          z
          cjson
          pthread)

set_target_properties(
  container_instances PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE BUILD_RPATH
                                                             "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  # ci_impl/tests is not in the tree yet; without this guard every TEST=1 build on
  # this branch dies at configure time, including other modules' tests.
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ci_impl/tests/CMakeLists.txt")
    add_subdirectory(ci_impl/tests)
  endif()
endif()
