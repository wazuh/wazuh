cmake_minimum_required(VERSION 3.12.4)

project(syscollectorimp_unit_test)

if(FSANITIZE)
set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")
endif()

link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/lib)

include_directories(${SRC_FOLDER}/data_provider/tests/mocks/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/)

file(GLOB SYSCOLLECTOR_IMP_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSCOLLECTOR_IMP_SRC
    "${CMAKE_SOURCE_DIR}/src/syscollectorImp.cpp"
    "${CMAKE_SOURCE_DIR}/src/syscollectorNormalizer.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_definitions(-DWAZUH_UNIT_TESTING)

add_executable(syscollectorimp_unit_test
    ${SYSCOLLECTOR_IMP_UNIT_TEST_SRC}
    ${SYSCOLLECTOR_IMP_SRC}
    ${DBSYNC_IMP_SRC})
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_custom_command(TARGET syscollectorimp_unit_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${SRC_FOLDER}/shared_modules/sync_protocol/build/bin/libagent_sync_protocol.dll"
        "$<TARGET_FILE_DIR:syscollectorimp_unit_test>/libagent_sync_protocol.dll"
        COMMENT "Copying libagent_sync_protocol.dll to test directory"
    )

    target_link_libraries(syscollectorimp_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        cjson
        sqlite3
        crypto
        ws2_32
        ssl
        crypt32
        agent_sync_protocol
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(syscollectorimp_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        sqlite3
        cjson
        crypto
        dl
        agent_sync_protocol
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME syscollectorimp_unit_test
         COMMAND syscollectorimp_unit_test)
