add_dependencies(${PROJECT_NAME} sqlite_unit_test)
project(sqlite_unit_test)

file(GLOB SQLITE_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SQLITE_SRC
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/sqlite/sqlite_wrapper.cpp")

add_executable(sqlite_unit_test
    ${SQLITE_UNIT_TEST_SRC}
    ${SQLITE_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(sqlite_unit_test
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
    target_link_libraries(sqlite_unit_test
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

add_test(NAME sqlite_unit_test
    COMMAND sqlite_unit_test)
