cmake_minimum_required(VERSION 3.10)

project(browser_extensions)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# TODO: Make sure this does not fail for Windows and Linux machines
include_directories(
  include
  ${CMAKE_SOURCE_DIR}/../external/nlohmann/
  ${CMAKE_CURRENT_SOURCE_DIR}/../wrappers/unix/darwin
)

link_directories(/opt/homebrew/lib)

set(SRC_FILES "")

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
