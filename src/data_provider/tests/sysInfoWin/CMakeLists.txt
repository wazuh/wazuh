add_dependencies(${PROJECT_NAME} sysInfoWindows_unit_test)
project(sysInfoWindows_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoWindows_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoWindows_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
    -static-libgcc -static-libstdc++
)

add_test(NAME sysInfoWindows_unit_test
    COMMAND sysInfoWindows_unit_test)

if(CMAKE_MEMORYCHECK_COMMAND)
    add_memcheck_test(sysInfoWindows_unit_test sysInfoWindows_unit_test)
endif()
