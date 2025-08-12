cmake_minimum_required(VERSION 3.12.4)

project(inventory_sync_tests)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/mocks)
set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)
set(COMPONENT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/component)
set(OPENSSL_DIR ${SRC_FOLDER}/external/openssl/include)

message("[?] Source directory: " ${TEST_SRC_DIR})
message("[?] Mocks directory: " ${TEST_MOCK_DIR})
message("[?] Unit test directory: " ${UNIT_SRC_DIR})
message("[?] Component tests directory: " ${COMPONENT_SRC_DIR})

file(GLOB UNIT_SRC_FILES
    ${UNIT_SRC_DIR}/*.cpp
    )

message("[?] Files to compile: " ${UNIT_SRC_FILES})

add_executable(inventory_sync_utest
    ${UNIT_SRC_FILES}
)

target_link_libraries(inventory_sync_utest
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    crypto
)

target_include_directories(inventory_sync_utest PRIVATE ${TEST_SRC_DIR} ${TEST_MOCK_DIR} ${OPENSSL_DIR})
add_test(NAME inventory_sync_utest COMMAND inventory_sync_utest)
set_tests_properties(inventory_sync_utest PROPERTIES LABELS "inventory_sync_utest")


# file(GLOB COMPONENT_SRC_FILES
#     ${COMPONENT_SRC_DIR}/*.cpp
#     )

# message("[?] Files to compile: " ${COMPONENT_SRC_FILES})

# add_executable(inventory_sync_ctest
#     ${COMPONENT_SRC_FILES}
# )

# target_link_libraries(inventory_sync_ctest
#     debug gtestd
#     debug gmockd
#     debug gtest_maind
#     debug gmock_maind
#     optimized gtest
#     optimized gmock
#     optimized gtest_main
#     optimized gmock_main
#     crypto
# )

# target_include_directories(inventory_sync_ctest PRIVATE ${TEST_SRC_DIR} ${TEST_MOCK_DIR})
# add_test(NAME inventory_sync_ctest COMMAND inventory_sync_ctest)
# set_tests_properties(inventory_sync_ctest PROPERTIES LABELS "inventory_sync_ctest")
