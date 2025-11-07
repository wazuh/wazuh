cmake_minimum_required(VERSION 3.12.4)

project(agent_info)

if(NOT CMAKE_BUILD_TYPE)
  if(CMAKE_SYMBOLS_IN_RELEASE MATCHES "ON")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  else()
    set(CMAKE_BUILD_TYPE Release)
  endif()
endif()

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++17 -pthread"
)

set(CMAKE_CXX_FLAGS_DEBUG "-g")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif(FSANITIZE)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

add_subdirectory(agent_info_impl)

include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/libpcre2/include/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/flatbuffers/include)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/filesystem/include/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include/)
include_directories(${SRC_FOLDER}/data_provider/include/)
include_directories(${SRC_FOLDER}/wazuh_modules/)
include_directories(${CMAKE_SOURCE_DIR}/include)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/file_helper/build/lib)
link_directories(${SRC_FOLDER}/data_provider/build/lib)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -D_WIN32_WINNT=0x600 -DWIN_EXPORT)
  link_directories(${SRC_FOLDER}/data_provider/build/bin)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

file(GLOB AGENT_INFO_SRC "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_library(agent_info SHARED ${AGENT_INFO_SRC} ${SRC_FOLDER}/${RESOURCE_OBJ})

target_link_libraries(agent_info AGENT_INFO_IMPL FileIO FilesystemWrapper)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    agent_info
    PROPERTIES PREFIX ""
               SUFFIX ".dll"
               LINK_FLAGS "-Wl,--add-stdcall-alias"
               POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
               # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  enable_testing()

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(agent_info -fprofile-arcs)
  else()
    target_link_libraries(agent_info gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
else()
  if(FSANITIZE)
    target_link_libraries(agent_info gcov)
  endif(FSANITIZE)
endif(UNIT_TEST)
