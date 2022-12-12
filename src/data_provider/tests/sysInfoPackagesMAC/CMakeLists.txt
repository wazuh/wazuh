add_dependencies(${PROJECT_NAME} sysInfoMacPackage_unit_test)
project(sysInfoMacPackage_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/data_provider/src/packages/packageMac.cpp")

add_executable(sysInfoMacPackage_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoMacPackage_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
)

if(APPLE)
    target_link_libraries(sysInfoMacPackage_unit_test ${SRC_FOLDER}/external/libplist/bin/lib/libplist-2.0.a)
endif(APPLE)

add_test(NAME sysInfoMacPackage_unit_test
    COMMAND sysInfoMacPackage_unit_test)
