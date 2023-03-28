
# Router test
add_executable(router_test
  ${TEST_SOURCE_DIR}/router/testAuxiliar/routerAuxiliarFunctions.cpp
  ${TEST_SOURCE_DIR}/router/router_test.cpp
  ${TEST_SOURCE_DIR}/router/runtimePolicy_test.cpp
  ${TEST_SOURCE_DIR}/router/policyManager_test.cpp


)
target_link_libraries(router_test engine_test_main base router builders rxbk store::fileDriver)
gtest_discover_tests(router_test)

# Runtime environment test
# TODO: Make a fake builder or something to avoid the need of the store
set(STORE_PATH_TEST "${CMAKE_CURRENT_SOURCE_DIR}/store_test/")
target_compile_definitions(router_test PRIVATE
  STORE_PATH_TEST="${STORE_PATH_TEST}"
)
