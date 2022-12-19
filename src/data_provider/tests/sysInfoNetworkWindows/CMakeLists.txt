add_dependencies(${PROJECT_NAME} sysInfoNetworkWindows_unit_test)
project(sysInfoNetworkWindows_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/data_provider/src/network/networkInterfaceWindows.cpp")

add_executable(sysInfoNetworkWindows_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoNetworkWindows_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
    -static-libgcc -static-libstdc++
)

add_test(NAME sysInfoNetworkWindows_unit_test
    COMMAND sysInfoNetworkWindows_unit_test)

if(CMAKE_MEMORYCHECK_COMMAND)
    add_memcheck_test(sysInfoNetworkWindows_unit_test sysInfoNetworkWindows_unit_test)
endif()
