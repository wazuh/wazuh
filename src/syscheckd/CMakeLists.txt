cmake_minimum_required(VERSION 3.12.4)

project(wazuh-syscheckd C CXX)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/audit-userspace/lib)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/procps/)
include_directories(${SRC_FOLDER}/external/flatbuffers/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/schema_validator/include/)
include_directories(${SRC_FOLDER}/config/include)
include_directories(${SRC_FOLDER}/rootcheck/include)
include_directories(${SRC_FOLDER}/os_crypto/md5)
include_directories(${SRC_FOLDER}/os_crypto/md5_sha1_sha256)
include_directories(${SRC_FOLDER}/os_crypto/sha1)
include_directories(${SRC_FOLDER}/os_net)
include_directories(${SRC_FOLDER}/os_regex)
include_directories(${SRC_FOLDER}/os_xml)
include_directories(${SRC_FOLDER}/wazuh_modules/include)
include_directories(${SRC_FOLDER}/wazuh_modules/src)
include_directories(${SRC_FOLDER}/wazuh_modules/src/agent_upgrade)
include_directories(${SRC_FOLDER}/wazuh_modules/src/task_manager)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/db/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/ebpf/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/file/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/recovery/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/registry/)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DARGV0="wazuh-syscheckd")
add_definitions(-DGROUPGLOBAL=wazuh)

if(INOTIFY_ENABLED)
  add_definitions(-DINOTIFY_ENABLED)
endif(INOTIFY_ENABLED)

if(ENABLE_AUDIT)
  add_definitions(-DENABLE_AUDIT)
endif(ENABLE_AUDIT)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

add_subdirectory("src/db")

file(
  GLOB
  SYSCHECKD_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/file/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/registry/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/whodata/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/recovery/*.c")

# Always build syscheckd library (without main.c) for unit tests
list(REMOVE_ITEM SYSCHECKD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
add_library(syscheckd_lib STATIC ${SYSCHECKD_SRC})
set_target_properties(syscheckd_lib PROPERTIES LINKER_LANGUAGE CXX)

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(syscheckd_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_definitions(syscheckd_lib PRIVATE _FORTIFY_SOURCE=0)
endif()

# Enable EVENTCHANNEL_SUPPORT for Windows builds
if(EVENTCHANNEL_SUPPORT)
  target_compile_definitions(syscheckd_lib PUBLIC EVENTCHANNEL_SUPPORT
                                                  _WIN32_WINNT=0x600)
endif()

target_link_libraries(
  syscheckd_lib
  PUBLIC fimdb
         wazuhext
         pthread
         config
         wazuh
         rootcheck
         agent_sync_protocol
         dbsync
         schema_validator)

if(UNIX)
  target_link_libraries(syscheckd_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(syscheckd_lib PUBLIC rt)
  endif(NOT APPLE)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory("src/ebpf")
    target_link_libraries(syscheckd_lib PUBLIC fimebpf)
  endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
endif(UNIX)

# Build Windows libraries always (needed by Makefile for final executables)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(wazuh-syscheckd STATIC ${SYSCHECKD_SRC})
  add_library(wazuh-syscheckd-event STATIC ${SYSCHECKD_SRC})
  target_compile_definitions(wazuh-syscheckd PUBLIC -D_WIN32_WINNT=0x600)
  if(UNIT_TEST)
    target_compile_definitions(wazuh-syscheckd PRIVATE WAZUH_UNIT_TESTING)
  endif()
  target_compile_definitions(wazuh-syscheckd-event
                             PUBLIC -D_WIN32_WINNT=0x600 -DEVENTCHANNEL_SUPPORT)
  if(UNIT_TEST)
    target_compile_definitions(wazuh-syscheckd-event PRIVATE WAZUH_UNIT_TESTING)
  endif()
  target_link_libraries(
    wazuh-syscheckd
    PRIVATE fimdb
            wazuhext
            pthread
            config
            wazuh
            rootcheck
            agent_sync_protocol
            dbsync
            schema_validator)
  target_link_libraries(
    wazuh-syscheckd-event
    PRIVATE fimdb
            wazuhext
            pthread
            config
            wazuh
            rootcheck
            agent_sync_protocol
            dbsync
            schema_validator)
  # Only build Linux executable when not running unit tests
elseif(NOT UNIT_TEST)
  add_executable(wazuh-syscheckd "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
  set_target_properties(
    wazuh-syscheckd PROPERTIES LINKER_LANGUAGE CXX RUNTIME_OUTPUT_DIRECTORY
                                                   ${SRC_FOLDER})
  target_link_libraries(wazuh-syscheckd PRIVATE syscheckd_lib)

  if(APPLE)
    # macOS
    set_target_properties(wazuh-syscheckd PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path/../lib"
    )
  else()
    # Linux/Unix
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
  endif()
endif()
