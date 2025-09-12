# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# Interface
add_library(scheduler_ischeduler INTERFACE)
target_include_directories(scheduler_ischeduler INTERFACE ${IFACE_DIR})
target_link_libraries(scheduler_ischeduler INTERFACE base)
add_library(scheduler::ischeduler ALIAS scheduler_ischeduler)

# Implementation
add_library(scheduler_scheduler STATIC
    ${SRC_DIR}/scheduler.cpp
)
target_include_directories(scheduler_scheduler
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(scheduler_scheduler
    PUBLIC
    scheduler::ischeduler
    base
)
add_library(scheduler::scheduler ALIAS scheduler_scheduler)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(scheduler_mocks INTERFACE)
target_include_directories(scheduler_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(scheduler_mocks INTERFACE GTest::gmock scheduler::ischeduler)
add_library(scheduler::mocks ALIAS scheduler_mocks)

# Component test
add_executable(scheduler_ctest
    ${COMPONENT_SRC_DIR}/scheduler_test.cpp
)

target_link_libraries(scheduler_ctest PRIVATE scheduler::scheduler GTest::gtest_main)
gtest_discover_tests(scheduler_ctest)

endif(ENGINE_BUILD_TEST)
