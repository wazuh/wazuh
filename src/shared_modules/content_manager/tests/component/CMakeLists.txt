cmake_minimum_required(VERSION 3.12.4)

project(content_manager_ctest)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

file(GLOB PROJECT_SOURCES *.cpp)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

# No gtest_main: main.cpp provides main() so that it can also define this binary's own
# Log::GLOBAL_LOG_FUNCTION. That symbol is hidden-visibility per DSO, so linking content_manager.so
# does not supply it and any TU here that emits an inline logging helper fails to link without it.
# Same arrangement as the unit suite.
target_link_libraries(
  ${PROJECT_NAME}
  debug
  gtestd
  debug
  gmockd
  optimized
  gtest
  optimized
  gmock
  rocksdb
  pthread)

# The pre-compiled rocksdb dependency (packages.wazuh.com) was built with GCC 14,
# which emits references to std::ios_base_library_init() not present in GCC 11's
# libstdc++ (Ubuntu 22). This flag suppresses the link-time check for undefined
# symbols in shared libraries; the symbol is harmlessly absent at runtime.
target_link_options(${PROJECT_NAME} PRIVATE -Wl,--allow-shlib-undefined)
target_link_libraries(${PROJECT_NAME} content_manager indexer_connector)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS ${PROJECT_NAME})
