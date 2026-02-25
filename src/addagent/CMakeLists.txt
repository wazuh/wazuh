cmake_minimum_required(VERSION 3.12.4)

project(manage_agents C)

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
  ${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256/
  ${SRC_FOLDER}/shared/os_crypto/sha1/
  ${SRC_FOLDER}/shared/os_crypto/signature/
  ${SRC_FOLDER}/shared/include/error_messages/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/libyaml/include/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/openssl/include/
  ${SRC_FOLDER}/external/zlib/
  ${SRC_FOLDER}/config/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/syscheckd/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/
  ${CMAKE_CURRENT_SOURCE_DIR}/include/)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-DARGV0="manage_agents")
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
file(GLOB ADDAGENT_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Build static library (without main.c) for unit tests and Windows agent
list(REMOVE_ITEM ADDAGENT_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
add_library(addagent_lib STATIC ${ADDAGENT_SRC})
set_target_properties(addagent_lib PROPERTIES LINKER_LANGUAGE C)

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(addagent_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_options(addagent_lib PRIVATE -O0 -g)
endif()

target_link_libraries(addagent_lib PUBLIC wazuhext pthread wazuh)

if(UNIX)
  target_link_libraries(addagent_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(addagent_lib PUBLIC rt)
  endif(NOT APPLE)
endif(UNIX)

# Build Windows library
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(wazuh-addagent STATIC ${ADDAGENT_SRC})
  target_compile_definitions(wazuh-addagent PUBLIC -D_WIN32_WINNT=0x600)
  if(UNIT_TEST)
    target_compile_definitions(wazuh-addagent PRIVATE WAZUH_UNIT_TESTING)
  endif()
  target_link_libraries(wazuh-addagent PRIVATE ${WAZUH_WINDOWS_LIBS} wazuh)

  if(NOT UNIT_TEST)
    # Build manage_agents.exe Windows executable
    add_executable(
      manage_agents_win
      ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c $<TARGET_OBJECTS:win32_service_rk>
      ${SRC_FOLDER}/win32/manage_agents.rc ${RESOURCE_OBJ_APP})
    target_compile_definitions(manage_agents_win PRIVATE ARGV0="manage-agents"
                                                         MA _WIN32_WINNT=0x600)
    set_target_properties(
      manage_agents_win PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/win32
                                   OUTPUT_NAME manage_agents)
    target_link_libraries(
      manage_agents_win
      PRIVATE wazuh-addagent
              wazuh
              ${WAZUH_WINDOWS_LIBS}
              wsock32
              wevtapi
              comctl32
              advapi32
              kernel32
              gdi32
              iphlpapi
              ws2_32
              crypt32
              wintrust)
  endif()
  # Only build Unix executable when not running unit tests
elseif(NOT UNIT_TEST)
  add_executable(manage_agents "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
  set_target_properties(
    manage_agents PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY
                                               ${SRC_FOLDER})
  target_link_libraries(manage_agents PRIVATE addagent_lib)

  if(APPLE)
    set_target_properties(
      manage_agents PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE
                               INSTALL_RPATH "@executable_path/../lib")
  else()
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
  endif()
endif()
