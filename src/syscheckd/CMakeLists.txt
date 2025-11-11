cmake_minimum_required(VERSION 3.12.4)

project(wazuh-syscheckd C CXX)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  if(CMAKE_SYMBOLS_IN_RELEASE MATCHES "ON")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  else()
    set(CMAKE_BUILD_TYPE Release)
  endif()
endif()

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)

include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/audit-userspace/lib)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/)
include_directories(${SRC_FOLDER}/external/flatbuffers/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src/db/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/ebpf/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/fim_recovery/include/)


link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib/)
link_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/lib)
link_directories(${SRC_FOLDER}/)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DARGV0="wazuh-syscheckd")

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
else()
 set(CMAKE_CXX_FLAGS_DEBUG "-g")
 if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS_DEBUG "-g --coverage")
 endif(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
 if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
   set(CMAKE_CXX_FLAGS_RELEASE "-O3")
 else()
   set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
 endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
endif(FSANITIZE)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

add_subdirectory("src/db")
add_subdirectory("src/fim_recovery")

file(GLOB SYSCHECKD_SRC
     "${CMAKE_SOURCE_DIR}/src/*.c"
     "${CMAKE_SOURCE_DIR}/src/file/*.c"
     "${CMAKE_SOURCE_DIR}/src/registry/*.c"
     "${CMAKE_SOURCE_DIR}/src/whodata/*.c")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_library(wazuh-syscheckd STATIC ${SYSCHECKD_SRC})
    add_library(wazuh-syscheckd-event STATIC ${SYSCHECKD_SRC})
    target_compile_definitions(wazuh-syscheckd PUBLIC -D_WIN32_WINNT=0x600)
    target_compile_definitions(wazuh-syscheckd-event PUBLIC -D_WIN32_WINNT=0x600 -DEVENTCHANNEL_SUPPORT)
else()
    add_executable(wazuh-syscheckd ${SYSCHECKD_SRC})
    set_target_properties(wazuh-syscheckd PROPERTIES LINKER_LANGUAGE CXX)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(wazuh-syscheckd PRIVATE fimdb fim_recovery wazuhext pthread wazuh rootcheck agent_sync_protocol dbsync)

if (UNIX)
    target_link_libraries(wazuh-syscheckd PRIVATE dl)
    if (NOT APPLE)
        target_link_libraries(wazuh-syscheckd PRIVATE rt)
        string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
    else()
        string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,@executable_path/../lib")
    endif(NOT APPLE)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_subdirectory("src/ebpf")
        target_link_libraries(wazuh-syscheckd PRIVATE fimebpf)
    endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
endif(UNIX)

if(UNIT_TEST)
  add_definitions(-DWAZUH_UNIT_TESTING)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(wazuh-syscheckd PRIVATE -fprofile-arcs cmocka)
  else()
    add_definitions(-fprofile-arcs -ftest-coverage)
    target_link_libraries(wazuh-syscheckd PRIVATE asan ubsan cmocka gcov -fprofile-arcs)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
else()
  if(FSANITIZE)
    target_link_libraries(wazuh-syscheckd PRIVATE gcov asan ubsan)
  elseif(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      target_link_libraries(wazuh-syscheckd PRIVATE -fprofile-arcs)
    else()
      target_link_libraries(wazuh-syscheckd PRIVATE gcov)
    endif()
  endif(FSANITIZE)
endif(UNIT_TEST)
