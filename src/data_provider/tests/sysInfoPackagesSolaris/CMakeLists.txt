project(sysInfoSolarisPackage_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
	"${CMAKE_SOURCE_DIR}/data_provider/src/packages/packageSolaris.cpp")

add_executable(sysInfoSolarisPackage_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoSolarisPackage_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
)

add_test(NAME sysInfoSolarisPackage_unit_test
	COMMAND sysInfoSolarisPackage_unit_test)
