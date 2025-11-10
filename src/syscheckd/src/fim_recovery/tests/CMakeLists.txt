cmake_minimum_required(VERSION 3.12.4)

project(fim_recovery_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

# Define OS_TYPE based on platform
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_definitions(-DOS_TYPE=OSType::WINDOWS)
else()
    add_definitions(-DOS_TYPE=OSType::OTHERS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

# Define PROMISE_TYPE for dbsync
add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

file(GLOB RECOVERY_TEST_SRC
    "*.cpp")

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/include/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/src/)
include_directories(${SRC_FOLDER}/headers/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)
link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/zlib/)

# Source files being tested
file(GLOB RECOVERY_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/recovery.cpp")

file(GLOB DB_SRC
    "${SRC_FOLDER}/syscheckd/src/db/src/db.cpp"
    "${SRC_FOLDER}/syscheckd/src/db/src/file.cpp"
    "${SRC_FOLDER}/syscheckd/src/db/src/dbFileItem.cpp")

file(GLOB DBSYNC_IMP_SRC
    "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
    "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

file(GLOB FIMDB_SRC
     "${SRC_FOLDER}/syscheckd/src/db/src/fimDB.cpp")

file(GLOB REGISTRY_SRC
    "${SRC_FOLDER}/syscheckd/src/db/src/dbRegistry*.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    file(GLOB WINDOWS_DB_SRC "${SRC_FOLDER}/syscheckd/src/db/src/fimDBSpecializationWindows.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_executable(fim_recovery_test
    ${RECOVERY_TEST_SRC}
    ${RECOVERY_SRC}
    ${DB_SRC}
    ${FIMDB_SRC}
    ${DBSYNC_IMP_SRC}
    ${WINDOWS_DB_SRC}
    ${REGISTRY_SRC})

target_link_libraries(fim_recovery_test
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
    wazuhext
    agent_sync_protocol
    z
    $<$<BOOL:${FSANITIZE}>:-fsanitize=address>
    $<$<BOOL:${FSANITIZE}>:-fsanitize=undefined>
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(fim_recovery_test
        ws2_32
        ssl
        crypt32
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(fim_recovery_test
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME fim_recovery_test
         COMMAND fim_recovery_test)
