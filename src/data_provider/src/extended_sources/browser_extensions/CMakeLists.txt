cmake_minimum_required(VERSION 3.12.4)

project(browser_extensions)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_FILES src/chrome.cpp src/firefox.cpp)

include_directories(include ${SRC_FOLDER}/external/nlohmann/
                    ${SRC_FOLDER}/external/openssl/include/)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/darwin)

  list(APPEND SRC_FILES src/safari_darwin.cpp)

  add_library(browser_extensions STATIC ${SRC_FILES})
  target_link_libraries(browser_extensions PRIVATE plist openssl_crypto)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/linux)

  add_library(browser_extensions STATIC ${SRC_FILES})
  target_link_libraries(browser_extensions PRIVATE openssl_crypto dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/windows/)

  list(APPEND SRC_FILES src/ie_explorer.cpp)

  add_library(browser_extensions STATIC ${SRC_FILES})
  target_link_libraries(
    browser_extensions PRIVATE openssl_crypto
    ws2_32 crypt32 version)
endif()

if(UNIT_TEST)
  add_coverage_libraries(browser_extensions)
  add_subdirectory(tests)
endif(UNIT_TEST)
