# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(wdb_iwdb INTERFACE)
target_include_directories(wdb_iwdb INTERFACE ${IFACE_DIR})
add_library(wdb::iwdb ALIAS wdb_iwdb)

add_library(wdb STATIC
    ${SRC_DIR}/wdbHandler.cpp
)
target_link_libraries(wdb PUBLIC wdb::iwdb sockiface::isock PRIVATE base)
target_include_directories(wdb
    PRIVATE
    ${SRC_DIR}
    ${INC_DIR}/wdb
    PUBLIC
    ${INC_DIR}
)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_executable(wdb_test
    ${TEST_SRC_DIR}/wdb_test.cpp
)

target_link_libraries(wdb_test gtest_main base wdb sockiface::mocks)
gtest_discover_tests(wdb_test)
endif(ENGINE_BUILD_TEST)
