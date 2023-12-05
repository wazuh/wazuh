# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(schemf_ischema INTERFACE)
target_include_directories(schemf_ischema INTERFACE ${IFACE_DIR})
target_link_libraries(schemf_ischema INTERFACE json base)
add_library(schemf::ischema ALIAS schemf_ischema)

add_library(schemf STATIC
  ${SRC_DIR}/schema.cpp
  ${SRC_DIR}/field.cpp
)

target_include_directories(schemf
PUBLIC
  ${INC_DIR}
PRIVATE
  ${SRC_DIR}
  ${INC_DIR}/schemf
)
target_link_libraries(schemf schemf::ischema)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_library(schemf_mocks INTERFACE)
target_include_directories(schemf_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(schemf_mocks INTERFACE gmock schemf::ischema)
add_library(schemf::mocks ALIAS schemf_mocks)

add_executable(schemf_utest
    ${UNIT_SRC_DIR}/field_test.cpp
)
target_link_libraries(schemf_utest PRIVATE schemf schemval gtest_main)
gtest_discover_tests(schemf_utest)

add_executable(schemf_ctest
    ${COMPONENT_SRC_DIR}/schema_test.cpp
)
target_link_libraries(schemf_ctest PRIVATE schemf schemval gtest_main)
gtest_discover_tests(schemf_ctest)

endif(ENGINE_BUILD_TEST)
