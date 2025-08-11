cmake_minimum_required(VERSION 3.10)

project(browser_extensions)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_FILES
  src/chrome.cpp
)

include_directories(
  include
  ${SRC_FOLDER}/external/nlohmann/
  ${SRC_FOLDER}/external/openssl/include/
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/darwin
  )

  list(APPEND SRC_FILES 
    src/safari_darwin.cpp
  )

  add_library(browser_extensions STATIC ${SRC_FILES})
  target_link_libraries(browser_extensions
    ${SRC_FOLDER}/external/libplist/bin/lib/libplist-2.0.a
    ${SRC_FOLDER}/external/openssl/libcrypto.a
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/linux
  )

  add_library(browser_extensions STATIC ${SRC_FILES})
  target_link_libraries(browser_extensions
    ${SRC_FOLDER}/external/openssl/libcrypto.a
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows/
  )

  add_library(browser_extensions STATIC ${SRC_FILES})
  target_link_libraries(browser_extensions
    ${SRC_FOLDER}/external/openssl/libcrypto.a
    ws2_32
    crypt32
  )
endif()

if(UNIT_TEST)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_link_libraries(browser_extensions -fprofile-arcs)
    else()
        target_link_libraries(browser_extensions gcov)
    endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

    add_subdirectory(tests)
endif(UNIT_TEST)