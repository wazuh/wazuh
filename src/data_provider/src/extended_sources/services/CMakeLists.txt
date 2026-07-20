cmake_minimum_required(VERSION 3.12.4)

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
    include_directories(${CMAKE_SOURCE_DIR}/../external/dbus/include/dbus-1.0)
    include_directories(
      ${CMAKE_SOURCE_DIR}/../external/dbus/lib/dbus-1.0/include)
    link_directories(${CMAKE_SOURCE_DIR}/../external/dbus/lib)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/linux)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/darwin)
  endif()
endif()

set(SRC_FILES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(
    APPEND SRC_FILES src/services_windows.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows/services_utils_wrapper.cpp)
  set(PLATFORM_LIBS_SERVICES netapi32)
else()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND SRC_FILES src/systemd_units_linux.cpp)
    set(PLATFORM_LIBS_SERVICES dbus-1 pthread)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND SRC_FILES src/launchd_darwin.cpp)
    set(PLATFORM_LIBS_SERVICES "-framework CoreFoundation")
  endif()
endif()

add_library(services STATIC ${SRC_FILES})

target_link_libraries(services PRIVATE ${PLATFORM_LIBS_SERVICES})

if(UNIT_TEST)
  add_coverage_libraries(services)
  add_subdirectory(tests)
endif(UNIT_TEST)
