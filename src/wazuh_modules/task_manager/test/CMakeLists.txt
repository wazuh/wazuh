cmake_minimum_required(VERSION 3.12.4)

project(task_manager_tests CXX)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
link_directories(${SRC_FOLDER}/external/googletest/lib)

file(GLOB UNIT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/unit/*.cpp)

add_executable(task_manager_utest ${UNIT_SRC_FILES})

set_target_properties(task_manager_utest PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON
                                                    CXX_EXTENSIONS OFF)

# Links the module's own .so rather than recompiling its sources. That is load-bearing, not a
# convenience: Log::GLOBAL_LOG_FUNCTION has hidden ELF visibility, so a definition compiled into
# this binary would be a DIFFERENT object from the one the module logs through, and nothing the
# tests assert about logging would hold.
target_link_libraries(
  task_manager_utest
  debug gtestd
  debug gmockd
  debug gtest_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  task_manager
  pthread
  wazuhext)

target_include_directories(
  task_manager_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
          ${CMAKE_CURRENT_LIST_DIR}/../src
          ${CMAKE_CURRENT_LIST_DIR}/mocks
          ${SRC_FOLDER}/shared_modules/utils
          ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/shared_modules/uds_http_server/include
          ${SRC_FOLDER}/shared_modules/metrics/include
          ${SRC_FOLDER}/external/cJSON
          ${SRC_FOLDER}/external/nlohmann
          ${SRC_FOLDER}/external/curl/include
          ${SRC_FOLDER})

add_test(NAME task_manager_utest COMMAND task_manager_utest)
set_tests_properties(task_manager_utest PROPERTIES LABELS task_manager_utest)
