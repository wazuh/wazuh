project(sysInfoPort_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/ports/portImpl.h")

add_executable(sysInfoPort_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoPort_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
)

add_test(NAME sysInfoPort_unit_test
         COMMAND sysInfoPort_unit_test)
