cmake_minimum_required(VERSION 3.12.4)

set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")

project(content_manager_test_tool)

enable_testing()

file(GLOB CONTENT_MANAGER_TEST_TOOL_SRC "*.cpp")

add_executable(content_manager_test_tool ${CONTENT_MANAGER_TEST_TOOL_SRC})

target_link_libraries(content_manager_test_tool
        content_manager
        pthread
        urlrequest)
