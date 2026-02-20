cmake_minimum_required(VERSION 3.12.4)

project(wazuh-agentd CXX)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/shared/os_net/
  ${SRC_FOLDER}/shared/os_regex/
  ${SRC_FOLDER}/shared/os_xml/
  ${SRC_FOLDER}/shared/os_crypto/md5/
  ${SRC_FOLDER}/shared/os_crypto/sha1/
  ${SRC_FOLDER}/shared/os_crypto/sha256/
  ${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256/
  ${SRC_FOLDER}/shared/os_crypto/signature/
  ${SRC_FOLDER}/shared/include/error_messages/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/libyaml/include/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/openssl/include/
  ${SRC_FOLDER}/config/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/os_execd/include/
  ${SRC_FOLDER}/logcollector/include/
  ${SRC_FOLDER}/monitord/
  ${SRC_FOLDER}/rootcheck/include/
  ${SRC_FOLDER}/syscheckd/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager/
  ${SRC_FOLDER}/wazuh_modules/src/task_manager/
  ${SRC_FOLDER}/wazuh_modules/sca/include/
  ${SRC_FOLDER}/shared_modules/agent_metadata/include/
  ${SRC_FOLDER}/shared_modules/common/
  ${CMAKE_CURRENT_SOURCE_DIR}/include/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-DARGV0="wazuh-agentd")
add_definitions(-DGROUPGLOBAL="wazuh")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

# Collect source files
file(GLOB AGENTD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(REMOVE_ITEM AGENTD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/agentd.cpp")
endif()

# Build static library (without main) for unit tests and Windows agent
list(REMOVE_ITEM AGENTD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
add_library(agentd_lib STATIC ${AGENTD_SRC})

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(agentd_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_options(agentd_lib PRIVATE -O0 -g)
endif()

target_link_libraries(agentd_lib PUBLIC wazuhext pthread agent_metadata config
                                        wazuh_modulesd_lib wazuh stdc++)

if(UNIX)
  target_link_libraries(agentd_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(agentd_lib PUBLIC rt)
  endif(NOT APPLE)
endif(UNIX)

# Build Windows libraries (needed by Makefile for final win32 executables)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(wazuh-agentd STATIC ${AGENTD_SRC})
  set_target_properties(wazuh-agentd PROPERTIES LINKER_LANGUAGE CXX)
  target_compile_definitions(wazuh-agentd PUBLIC -D_WIN32_WINNT=0x600)
  if(UNIT_TEST)
    target_compile_definitions(wazuh-agentd PRIVATE WAZUH_UNIT_TESTING)
  endif()
  target_link_libraries(wazuh-agentd PRIVATE wazuhext pthread agent_metadata
                                             config wazuh_modulesd_lib wazuh)
  # Only build Unix executable when not running unit tests
elseif(NOT UNIT_TEST)
  add_executable(wazuh-agentd "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
  set_target_properties(
    wazuh-agentd PROPERTIES LINKER_LANGUAGE CXX RUNTIME_OUTPUT_DIRECTORY
                                                 ${SRC_FOLDER})
  target_link_libraries(wazuh-agentd PRIVATE agentd_lib)

  if(APPLE)
    set_target_properties(
      wazuh-agentd PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE
                              INSTALL_RPATH "@executable_path/../lib")
  else()
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
  endif()
endif()
