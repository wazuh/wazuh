project(sysInfoPackagesLinuxHelper_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoPackagesLinuxHelper_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoPackagesLinuxHelper_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    alpm
    archive
    ssl
    crypto
    cjson
    proc
    dl
)

add_test(NAME sysInfoPackagesLinuxHelper_unit_test
         COMMAND sysInfoPackagesLinuxHelper_unit_test)
