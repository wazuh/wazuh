project(sysInfoNetworkBSD_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/data_provider/src/network/networkInterfaceBSD.cpp")

add_executable(sysInfoNetworkBSD_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoNetworkBSD_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
    dl
)
add_test(NAME sysInfoNetworkBSD_unit_test
         COMMAND sysInfoNetworkBSD_unit_test)
