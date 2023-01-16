# Router test
add_executable(router_test
  ${TEST_SOURCE_DIR}/router/router_test.cpp
)
target_link_libraries(router_test engine_test_main base router builders)
gtest_discover_tests(router_test)

# Router + rxkb test
add_executable(rxbk_router_test
  ${TEST_SOURCE_DIR}/router/rxbk_router_test.cpp
)
target_link_libraries(rxbk_router_test engine_test_main base router builders rxbk)
gtest_discover_tests(rxbk_router_test)

# Runtime environment test
# TODO: Make a fake builder or something to avoid the need of the store
set(STORE_PATH_TEST "${CMAKE_CURRENT_SOURCE_DIR}/store_test/")

add_executable(runtimeEnvironment_test
  ${TEST_SOURCE_DIR}/router/testAuxiliar/routerAuxiliarFunctions.cpp
  ${TEST_SOURCE_DIR}/router/runtimeEnvironment_test.cpp
)
target_link_libraries(runtimeEnvironment_test engine_test_main base router builders rxbk store::fileDriver)
include_directories(${TEST_SOURCE_DIR}/router/testAuxiliar)

target_compile_definitions(runtimeEnvironment_test PRIVATE
  STORE_PATH_TEST="${STORE_PATH_TEST}"
)
gtest_discover_tests(runtimeEnvironment_test)
