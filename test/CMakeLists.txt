
set(TEST_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/source)

# Add googletest as CPM dependency
include(../cmake/CPM.cmake)
CPMAddPackage(
    NAME googletest
    GITHUB_REPOSITORY google/googletest
    GIT_TAG release-1.11.0
    VERSION 1.11.0
    OPTIONS
    "INSTALL_GTEST OFF"
    EXCLUDE_FROM_ALL YES
)

include(GoogleTest)

add_subdirectory(${TEST_SOURCE_DIR}/mocks)
add_subdirectory(${TEST_SOURCE_DIR}/base)
add_subdirectory(${TEST_SOURCE_DIR}/defs)
add_subdirectory(${TEST_SOURCE_DIR}/schemf)
add_subdirectory(${TEST_SOURCE_DIR}/builder)
add_subdirectory(${TEST_SOURCE_DIR}/cmds)
add_subdirectory(${TEST_SOURCE_DIR}/hlp)
add_subdirectory(${TEST_SOURCE_DIR}/logpar)
add_subdirectory(${TEST_SOURCE_DIR}/json)
add_subdirectory(${TEST_SOURCE_DIR}/yml)
add_subdirectory(${TEST_SOURCE_DIR}/kvdb)
add_subdirectory(${TEST_SOURCE_DIR}/router)
add_subdirectory(${TEST_SOURCE_DIR}/rxbk)
add_subdirectory(${TEST_SOURCE_DIR}/conf)
add_subdirectory(${TEST_SOURCE_DIR}/queue)
add_subdirectory(${TEST_SOURCE_DIR}/server)
