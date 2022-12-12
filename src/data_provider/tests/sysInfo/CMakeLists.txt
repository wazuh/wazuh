add_dependencies(${PROJECT_NAME} sysinfo_unit_test)
project(sysinfo_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/data_provider/src/sysInfo.cpp"
    "${CMAKE_SOURCE_DIR}/data_provider/src/osinfo/sysOsParsers.cpp")

add_executable(sysinfo_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(sysinfo_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        sqlite3
        cjson
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(sysinfo_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        sqlite3
        cjson
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME sysinfo_unit_test
    COMMAND sysinfo_unit_test)
