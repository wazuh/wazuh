add_dependencies(${PROJECT_NAME} rsyncInterface_unit_test)
project(rsyncInterface_unit_test)

file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp"
    "${CMAKE_SOURCE_DIR}/shared_modules/rsync/src/*.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(rsyncInterface_unit_test
    ${INTERFACE_UNITTEST_SRC}
    ${DBSYNC_IMP_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(rsyncInterface_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        cjson
        sqlite3
        crypto
        ws2_32
        crypt32
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(rsyncInterface_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        cjson
        sqlite3
        crypto
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME rsyncInterface_unit_test
    COMMAND rsyncInterface_unit_test)
