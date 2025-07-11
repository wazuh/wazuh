cmake_minimum_required(VERSION 3.10)

project(services)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../external/nlohmann/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include_directories(${CMAKE_SOURCE_DIR}/../shared_modules/utils)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows)
else()
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/linux)
  endif()
endif()

set(SRC_FILES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND SRC_FILES src/services_windows.cpp)
  #set(PLATFORM_LIBS_SERVICES netapi32 advapi32)
else()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND SRC_FILES src/systemd_units_linux.cpp)
  endif()
endif()

add_library(services STATIC ${SRC_FILES})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # target_link_libraries(services
  #     wtsapi32
  #     ${PLATFORM_LIBS_SERVICES}
  # )
endif()

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(services -fprofile-arcs)
  else()
    target_link_libraries(services gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
endif(UNIT_TEST)
