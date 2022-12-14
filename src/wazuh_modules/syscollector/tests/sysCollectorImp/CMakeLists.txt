add_dependencies(${PROJECT_NAME} syscollectorimp_unit_test)
project(syscollectorimp_unit_test)

link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)

file(GLOB SYSCOLLECTOR_IMP_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSCOLLECTOR_IMP_SRC
    "${CMAKE_SOURCE_DIR}/wazuh_modules/syscollector/src/syscollectorImp.cpp"
    "${CMAKE_SOURCE_DIR}/wazuh_modules/syscollector/src/syscollectorNormalizer.cpp")

file(GLOB RSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/rsync/src/*.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_definitions(-DWAZUH_UNIT_TESTING)

add_executable(syscollectorimp_unit_test
    ${SYSCOLLECTOR_IMP_UNIT_TEST_SRC}
    ${SYSCOLLECTOR_IMP_SRC}
    ${RSYNC_IMP_SRC}
    ${DBSYNC_IMP_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(syscollectorimp_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        cjson
        sqlite3
        crypto
        ws2_32
        ssl
        crypt32
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(syscollectorimp_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        sqlite3
        cjson
        crypto
        dl
    )
endif()

add_test(NAME syscollectorimp_unit_test
    COMMAND syscollectorimp_unit_test)
