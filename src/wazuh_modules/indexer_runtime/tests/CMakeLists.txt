cmake_minimum_required(VERSION 3.12.4)

project(wm_indexer_runtime_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
link_directories(${SRC_FOLDER}/external/googletest/lib)

file(GLOB UNIT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/unit/*.cpp)

add_executable(wm_indexer_runtime_utest ${UNIT_SRC_FILES} $<TARGET_OBJECTS:wm_indexer_runtime_objects>)

target_link_libraries(
  wm_indexer_runtime_utest
  debug gtestd
  debug gtest_maind
  optimized gtest
  optimized gtest_main
  indexer_client
  keystore
  wazuhext
  pthread)

target_include_directories(wm_indexer_runtime_utest PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
                                                            ${CMAKE_CURRENT_LIST_DIR}/../src ${SRC_FOLDER}/external/nlohmann)

add_test(NAME wm_indexer_runtime_utest COMMAND wm_indexer_runtime_utest)
set_tests_properties(wm_indexer_runtime_utest PROPERTIES LABELS wm_indexer_runtime_utest)
