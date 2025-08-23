# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(scheduler STATIC
    ${SRC_DIR}/scheduler.cpp
)
target_include_directories(scheduler
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(scheduler
    PUBLIC
    base
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(scheduler_ctest
    ${COMPONENT_SRC_DIR}/scheduler_test.cpp
)

target_link_libraries(scheduler_ctest PRIVATE scheduler GTest::gtest_main)
gtest_discover_tests(scheduler_ctest)

endif(ENGINE_BUILD_TEST)
