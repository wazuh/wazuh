cmake_minimum_required(VERSION 3.12.4)

project(router_test_tool)

enable_testing()

file(GLOB ROUTER_TEST_TOOL_SRC "*.cpp")

add_executable(router_test_tool ${ROUTER_TEST_TOOL_SRC})

target_link_libraries(router_test_tool router pthread flatbuffers)
target_include_directories(router_test_tool PUBLIC ${SRC_FOLDER}/external/flatbuffers/include)
target_link_directories(router_test_tool PUBLIC ${SRC_FOLDER}/external/flatbuffers/build)
