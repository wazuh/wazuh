project(sysInfoPackagesBerkeleyDB_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoPackagesBerkeleyDB_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoPackagesBerkeleyDB_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
    proc
    dl
)

add_test(NAME sysInfoPackagesBerkeleyDB_unit_test
         COMMAND sysInfoPackagesBerkeleyDB_unit_test)
