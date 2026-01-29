cmake_minimum_required(VERSION 3.12.4)

project(content_manager_test_tool)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB CONTENT_MANAGER_TEST_TOOL_SRC "*.cpp")

add_executable(content_manager_test_tool ${CONTENT_MANAGER_TEST_TOOL_SRC})

target_link_libraries(content_manager_test_tool content_manager pthread
                      urlrequest)
