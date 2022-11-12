project(dbsync_unit_test)

file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp"
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(dbsync_unit_test
    ${INTERFACE_UNITTEST_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dbsync_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        sqlite3
        cjson
        pthread
        -static-libgcc -static-libstdc++)
else()
    target_link_libraries(dbsync_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        sqlite3
        cjson
        pthread
        dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME dbsync_unit_test
         COMMAND dbsync_unit_test)
