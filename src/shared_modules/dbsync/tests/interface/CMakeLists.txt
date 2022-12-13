add_dependencies(${PROJECT_NAME} dbsyncInterface_unit_test)
project(dbsyncInterface_unit_test)

file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp"
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(dbsyncInterface_unit_test
    ${INTERFACE_UNITTEST_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dbsyncInterface_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        sqlite3
        cjson
        pthread
        -static-libgcc -static-libstdc++)
else()
    target_link_libraries(dbsyncInterface_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        sqlite3
        cjson
        pthread
        dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME dbsyncInterface_unit_test
    COMMAND dbsyncInterface_unit_test)
