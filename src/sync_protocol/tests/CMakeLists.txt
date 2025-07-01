cmake_minimum_required(VERSION 3.12.4)

project(agent_sync_protocol_tests)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,leak,undefined")
endif(FSANITIZE)

message(STATUS "SRC_FOLDER is: ${SRC_FOLDER}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../external/googletest/googletest/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../external/googletest/googlemock/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../external/sqlite/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../external/flatbuffers/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../shared_modules/utils/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../external/googletest/lib/)

# Add the test executable
add_executable(agent_sync_protocol_tests
    main.cpp
    test_persistent_queue_storage.cpp
    test_persistent_queue.cpp
)

# Include paths
target_include_directories(agent_sync_protocol_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_BINARY_DIR}/..
)

# Link test executable to the main library and GTest
target_link_libraries(agent_sync_protocol_tests
    PRIVATE
    agent_sync_protocol
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
)
