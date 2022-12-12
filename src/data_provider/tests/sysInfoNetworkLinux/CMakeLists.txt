add_dependencies(${PROJECT_NAME} sysInfoNetworkLinux_unit_test)
project(sysInfoNetworkLinux_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/data_provider/src/network/networkInterfaceLinux.cpp")

add_executable(sysInfoNetworkLinux_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoNetworkLinux_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
    dl
)

add_test(NAME sysInfoNetworkLinux_unit_test
    COMMAND sysInfoNetworkLinux_unit_test)
