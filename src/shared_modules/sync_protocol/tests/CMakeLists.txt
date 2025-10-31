cmake_minimum_required(VERSION 3.12.4)

project(agent_sync_protocol_tests)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

if(FSANITIZE)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,leak,undefined")
endif(FSANITIZE)

message(STATUS "SRC_FOLDER is: ${SRC_FOLDER}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../external/googletest/googletest/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../external/googletest/googlemock/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../external/sqlite/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../external/flatbuffers/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../utils/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../headers/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../external/googletest/lib/)

# Add the test executable
add_executable(agent_sync_protocol_tests
    main.cpp
    test_agent_sync_protocol.cpp
    test_persistent_queue_storage.cpp
    test_persistent_queue.cpp
    test_metadata_provider.cpp
)

# Include paths
target_include_directories(agent_sync_protocol_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_BINARY_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../file_helper/filesystem/tests/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../file_helper/filesystem/include
)

target_link_libraries(agent_sync_protocol_tests
    PRIVATE
    agent_sync_protocol
    debug gtestd
    debug gmockd
    optimized gtest
    optimized gmock
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_custom_command(TARGET agent_sync_protocol_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_BINARY_DIR}/../bin/libagent_sync_protocol.dll"
        "$<TARGET_FILE_DIR:agent_sync_protocol_tests>/libagent_sync_protocol.dll"
        COMMENT "Copying libagent_sync_protocol.dll to test directory"
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME agent_sync_protocol_tests COMMAND agent_sync_protocol_tests)
