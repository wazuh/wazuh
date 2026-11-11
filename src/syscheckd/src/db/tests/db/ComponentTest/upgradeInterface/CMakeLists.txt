cmake_minimum_required(VERSION 3.12.4)

project(fim_db_upgrade_test)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
file(GLOB DB_UPGRADE_TEST_SRC "*.cpp")

include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/src/)

# The test drives DBSync directly rather than going through DB::init, which
# hardcodes the real on-disk path, so only the engine itself is needed here.
file(GLOB DBSYNC_IMP_SRC "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
     "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(fim_db_upgrade_test ${DB_UPGRADE_TEST_SRC} ${DBSYNC_IMP_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(
    fim_db_upgrade_test
    debug
    gtestd
    debug
    gmockd
    debug
    gtest_maind
    debug
    gmock_maind
    optimized
    gtest
    optimized
    gmock
    optimized
    gtest_main
    optimized
    gmock_main
    pthread
    sqlite3
    cjson
    crypto
    ws2_32
    ssl
    crypt32
    -static-libgcc
    -static-libstdc++)
else()
  target_link_libraries(
    fim_db_upgrade_test
    debug
    gtestd
    debug
    gmockd
    debug
    gtest_maind
    debug
    gmock_maind
    optimized
    gtest
    optimized
    gmock
    optimized
    gtest_main
    optimized
    gmock_main
    pthread
    sqlite3
    crypto
    cjson
    dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME fim_db_upgrade_test COMMAND fim_db_upgrade_test)

set_tests_properties(fim_db_upgrade_test PROPERTIES LABELS "syscheckd")
