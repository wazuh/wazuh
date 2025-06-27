# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

## Interface
add_library(bk_ibk INTERFACE)
target_include_directories(bk_ibk INTERFACE ${IFACE_DIR})
target_link_libraries(bk_ibk INTERFACE base) # Base for expression
add_library(bk::ibk ALIAS bk_ibk)

# TaskFlow
set(TASKF_SRC_DIR ${SRC_DIR}/taskf)

add_library(bk_taskf STATIC
    ${TASKF_SRC_DIR}/controller.cpp
)
target_include_directories(bk_taskf
    PUBLIC
    ${INC_DIR}
    ${Taskflow_SOURCE_DIR}

    PRIVATE
    ${TASKF_SRC_DIR}
    ${INC_DIR}/bk/taskf
)
target_link_libraries(bk_taskf PUBLIC Taskflow::Taskflow bk::ibk)
add_library(bk::taskf ALIAS bk_taskf)

# RxCpp
set(RXCPP_SRC_DIR ${SRC_DIR}/rx)

add_library(bk_rx STATIC
    ${RXCPP_SRC_DIR}/controller.cpp
)
target_include_directories(bk_rx
    PUBLIC
    ${INC_DIR}
    ${RxCpp_SOURCE_DIR}/Rx/v2/src

    PRIVATE
    ${RXCPP_SRC_DIR}
    ${INC_DIR}/bk/rx
)
target_link_libraries(bk_rx PUBLIC RxCpp::RxCpp bk::ibk)
add_library(bk::rx ALIAS bk_rx)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
add_library(bk_mocks INTERFACE)
target_include_directories(bk_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(bk_mocks INTERFACE GTest::gmock bk::ibk)
add_library(bk::mocks ALIAS bk_mocks)

## Backend component test
add_executable(bk_ctest
    ${COMPONENT_SRC_DIR}/bk_test.cpp
)
target_link_libraries(bk_ctest GTest::gtest_main bk::taskf bk::rx bk::mocks)
gtest_discover_tests(bk_ctest)

endif(ENGINE_BUILD_TEST)
