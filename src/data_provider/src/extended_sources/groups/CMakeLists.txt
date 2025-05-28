cmake_minimum_required(VERSION 3.10)

project(user_groups)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../../../../external/nlohmann/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include_directories(${CMAKE_SOURCE_DIR}/../shared_modules/utils)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows)
else()
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/linux)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/darwin)
  endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(SRC_FILES src/user_groups_windows.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows/users_utils_wrapper.cpp 
      ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows/groups_utils_wrapper.cpp)
      set(PLATFORM_LIBS_USERS netapi32 advapi32)
else()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(SRC_FILES src/user_groups_linux.cpp)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        find_library(OPEN_DIRECTORY OpenDirectory)
        find_library(FOUNDATION Foundation)

        set(SRC_FILES src/user_groups_darwin.cpp src/od_wrapper.mm)
        set(PLATFORM_LIBS_USERS ${OPEN_DIRECTORY} ${FOUNDATION})
    endif()
endif()

add_library(user_groups STATIC ${SRC_FILES})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(user_groups
    wtsapi32
    ${PLATFORM_LIBS_USERS}
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_link_libraries(user_groups ${PLATFORM_LIBS_USERS})
endif()

if(UNIT_TEST)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_link_libraries(user_groups -fprofile-arcs)
    else()
        target_link_libraries(user_groups gcov)
    endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

    add_subdirectory(tests)
endif(UNIT_TEST)
