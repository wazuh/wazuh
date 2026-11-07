# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.12.4)

project(content_manager_test_tool)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB CONTENT_MANAGER_TEST_TOOL_SRC "*.cpp")

add_executable(content_manager_test_tool ${CONTENT_MANAGER_TEST_TOOL_SRC})

# The tool starts the process's indexer_client runtime itself, as a host does (RuntimeOwner + Client), and hands the
# Client to content_manager's v2 adapter.
target_link_libraries(content_manager_test_tool content_manager indexer_client pthread)
