cmake_minimum_required(VERSION 3.12.4)

project(users)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../external/nlohmann/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include_directories(${CMAKE_SOURCE_DIR}/../shared_modules/utils)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows)
else()
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix)
  include_directories(
    ${CMAKE_SOURCE_DIR}/../shared_modules/file_helper/filesystem/include)
  if(NOT DEFINED WAZUH_MAIN_PROJECT)
    get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
  endif()
  link_directories(${SRC_FOLDER}/shared_modules/file_helper/build)
  link_directories(${SRC_FOLDER}/shared_modules/file_helper/build/lib)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/linux)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/darwin)
  endif()
endif()

set(SRC_FILES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND SRC_FILES src/logged_in_users_win.cpp)
  list(APPEND SRC_FILES src/users_windows.cpp
       ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows/users_utils_wrapper.cpp)
  set(PLATFORM_LIBS_USERS netapi32 advapi32)
else()
  list(APPEND SRC_FILES src/sudoers_unix.cpp)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND SRC_FILES src/logged_in_users_linux.cpp)
    list(APPEND SRC_FILES src/shadow_linux.cpp)
    list(APPEND SRC_FILES src/users_linux.cpp)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND SRC_FILES src/logged_in_users_darwin.cpp)
    find_library(OPEN_DIRECTORY OpenDirectory)
    find_library(FOUNDATION Foundation)

    list(APPEND SRC_FILES src/users_darwin.cpp
         ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/darwin/od_wrapper.mm)
    set(PLATFORM_LIBS_USERS ${OPEN_DIRECTORY} ${FOUNDATION})
  endif()
endif()

add_library(users STATIC ${SRC_FILES})
target_link_libraries(users PRIVATE FilesystemWrapper)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(users PRIVATE wtsapi32 ${PLATFORM_LIBS_USERS})
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_link_libraries(users PRIVATE ${PLATFORM_LIBS_USERS})
endif()

if(UNIT_TEST)
  add_coverage_libraries(users)
  add_subdirectory(tests)
endif(UNIT_TEST)
