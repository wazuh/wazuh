add_dependencies(${PROJECT_NAME} sysInfoPackageLinuxParserRPM_unit_test)
project(sysInfoPackageLinuxParserRPM_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB PARSER_SRC "${CMAKE_SOURCE_DIR}/data_provider/src/packages/packageLinuxParserRpm.cpp")
file(GLOB RPM_SRC "${CMAKE_SOURCE_DIR}/data_provider/src/packages/rpm*.cpp")

add_executable(sysInfoPackageLinuxParserRPM_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${RPM_SRC}
    ${PARSER_SRC})

set_property(TARGET sysInfoPackageLinuxParserRPM_unit_test PROPERTY COMPILE_FLAGS "-Wno-unused-parameter")

target_link_libraries(sysInfoPackageLinuxParserRPM_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    dl
)

add_test(NAME sysInfoPackageLinuxParserRPM_unit_test
    COMMAND sysInfoPackageLinuxParserRPM_unit_test)

if(CMAKE_MEMORYCHECK_COMMAND)
    add_memcheck_test(sysInfoPackageLinuxParserRPM_unit_test sysInfoPackageLinuxParserRPM_unit_test)
endif()
