cmake_minimum_required(VERSION 3.12.4)

project(content_manager_utest)

# Copy input files to the build directory
file(COPY input_files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

# Include directories
include_directories(${SRC_FOLDER}/shared_modules/http-request/include)

file(GLOB PROJECT_SOURCES *.cpp)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

# The pre-compiled rocksdb dependency (packages.wazuh.com) was built with GCC 14,
# which emits references to std::ios_base_library_init() not present in GCC 11's
# libstdc++ (Ubuntu 22). This flag suppresses the link-time check for undefined
# symbols in shared libraries; the symbol is harmlessly absent at runtime.
target_link_options(${PROJECT_NAME} PRIVATE -Wl,--allow-shlib-undefined)

target_link_libraries(
  ${PROJECT_NAME}
  content_manager
  debug
  gtestd
  debug
  gmockd
  optimized
  gtest
  optimized
  gmock
  urlrequest
  wazuhext
  lzma
  rocksdb
  pthread)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS ${PROJECT_NAME})
