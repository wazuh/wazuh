cmake_minimum_required(VERSION 3.12.4)

project(https_client_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

# runValgrind discovers module test binaries in build/bin by the
# "<module basename>*_test" naming; keep both properties intact.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)

file(GLOB UNIT_SRC_FILES ${UNIT_SRC_DIR}/*.cpp)

add_executable(https_client_unit_test ${UNIT_SRC_FILES})

target_link_libraries(
  https_client_unit_test
  debug gtestd
  debug gmockd
  optimized gtest
  optimized gmock
  https_client
  pthread)

target_include_directories(
  https_client_unit_test
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
          ${CMAKE_CURRENT_LIST_DIR}/../src
          ${UNIT_SRC_DIR}/mocks
          ${SRC_FOLDER}
          ${SRC_FOLDER}/shared_modules/utils
          ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/external/cJSON)

if(HTTPS_CLIENT_TSAN)
  target_compile_options(https_client_unit_test PRIVATE -fsanitize=thread -g)
  target_link_options(https_client_unit_test PRIVATE -fsanitize=thread)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_custom_command(
    TARGET https_client_unit_test
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_BINARY_DIR}/lib/libhttps_client.dll"
            "$<TARGET_FILE_DIR:https_client_unit_test>"
    COMMENT "Copying libhttps_client.dll next to the test executable")
endif()

add_test(NAME https_client_unit_test COMMAND https_client_unit_test)
set_tests_properties(https_client_unit_test PROPERTIES LABELS "https_client")
