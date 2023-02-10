add_dependencies(${PROJECT_NAME} RpmPackageManager_unit_test)
project(RpmPackageManager_unit_test)

file(GLOB RPM_UNIT_TEST_SRC "*.cpp")
file(GLOB RPM_SRC "${CMAKE_SOURCE_DIR}/data_provider/src/packages/rpm*.cpp")

add_executable(RpmPackageManager_unit_test ${RPM_UNIT_TEST_SRC} ${RPM_SRC})

target_link_libraries(RpmPackageManager_unit_test
    gtest
    gmock
    gtest_main
    gmock_main
    pthread
    sqlite3
    cjson
    proc
    dl
)

add_test(NAME RpmPackageManager_unit_test
    COMMAND RpmPackageManager_unit_test)

if(CMAKE_MEMORYCHECK_COMMAND)
    add_memcheck_test(RpmPackageManager_unit_test RpmPackageManager_unit_test)
endif()
