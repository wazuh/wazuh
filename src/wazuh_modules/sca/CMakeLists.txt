cmake_minimum_required(VERSION 3.12.4)

project(sca)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++17 -pthread"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

add_subdirectory(sca_impl)

include_directories(${SRC_FOLDER}/shared/include)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/flatbuffers/include)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${CMAKE_BINARY_DIR}/shared_modules/sync_protocol)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(
  ${SRC_FOLDER}/shared_modules/file_helper/filesystem/include/)
include_directories(${SRC_FOLDER}/wazuh_modules/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/shared_modules/sync_protocol)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  link_directories(${SRC_FOLDER}/external/libdb/build_unix/)
  link_directories(${SRC_FOLDER}/external/dbus/lib/)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -D_WIN32_WINNT=0x600 -DWIN_EXPORT)
  link_directories(${CMAKE_BINARY_DIR}/bin)
else()
  link_directories(${CMAKE_BINARY_DIR}/lib)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

file(GLOB SCA_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(sca SHARED ${SCA_SRC} ${RESOURCE_OBJ_DLL})

target_link_libraries(sca PRIVATE SCAImpl)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    sca
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
  add_coverage_libraries(sca)
endif(UNIT_TEST)
