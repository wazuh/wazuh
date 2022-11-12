project(rsync_unit_test)

file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp"
    "${CMAKE_SOURCE_DIR}/shared_modules/rsync/src/*.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(rsync_unit_test
    ${INTERFACE_UNITTEST_SRC}
    ${DBSYNC_IMP_SRC} )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(rsync_unit_test
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
    target_link_libraries(rsync_unit_test
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

add_test(NAME rsync_unit_test
         COMMAND rsync_unit_test)
