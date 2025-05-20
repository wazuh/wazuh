# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(rbac_irbac INTERFACE)
target_include_directories(rbac_irbac INTERFACE ${IFACE_DIR})
add_library(rbac::irbac ALIAS rbac_irbac)

add_library(rbac STATIC
  ${SRC_DIR}/rbac.cpp
)
target_include_directories(rbac
PUBLIC
  ${INC_DIR}
PRIVATE
  ${SRC_DIR}
  ${INC_DIR}/rbac
)
target_link_libraries(rbac PUBLIC rbac::irbac PRIVATE base store::istore)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_library(rbac_mocks INTERFACE)

target_include_directories(rbac_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(rbac_mocks INTERFACE GTest::gmock rbac::irbac)
add_library(rbac::mocks ALIAS rbac_mocks)

add_executable(rbac_test
  ${TEST_SRC_DIR}/rbac_test.cpp
  ${TEST_SRC_DIR}/permission_test.cpp
  ${TEST_SRC_DIR}/role_test.cpp
)

target_include_directories(rbac_test
    PRIVATE
    ${TEST_SRC_DIR}
)

target_link_libraries(rbac_test GTest::gtest_main base rbac store::mocks)
gtest_discover_tests(rbac_test)

endif(ENGINE_BUILD_TEST)
