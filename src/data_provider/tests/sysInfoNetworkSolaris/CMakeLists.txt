add_dependencies(${PROJECT_NAME} sysInfoNetworkSolaris_unit_test)
project(sysInfoNetworkSolaris_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/data_provider/src/network/networkInterfaceSolaris.cpp")

add_executable(sysInfoNetworkSolaris_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoNetworkSolaris_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
    dl
)

add_test(NAME sysInfoNetworkSolaris_unit_test
    COMMAND sysInfoNetworkSolaris_unit_test)
