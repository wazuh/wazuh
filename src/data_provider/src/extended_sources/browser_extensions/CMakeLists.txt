cmake_minimum_required(VERSION 3.10)

project(browser_extensions)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_FILES "")

include_directories(
  include
  ${SRC_FOLDER}/external/nlohmann/
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
  )

  if(UNIT_TEST)
    target_link_libraries(browser_extensions -fprofile-arcs)
    add_subdirectory(tests)
  endif(UNIT_TEST)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  include_directories(
    ${SRC_FOLDER}/external/openssl/include/
  )

  list(APPEND SRC_FILES 
    src/chrome.cpp
  )

  add_library(chrome_extensions STATIC ${SRC_FILES})
  target_link_libraries(chrome_extensions
    ${SRC_FOLDER}/external/openssl/libcrypto.a
  )

  add_executable(chrome_main src/main.cpp)
  target_link_libraries(chrome_main chrome_extensions)
endif()
