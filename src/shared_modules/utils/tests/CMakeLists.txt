cmake_minimum_required(VERSION 3.12.4)

project(utils_unit_test)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/rocksdb/build/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/lzma/build/)
link_directories(${SRC_FOLDER}/external/zlib/contrib/minizip/)

include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/lzma/src/liblzma/api)
include_directories(${SRC_FOLDER}/external/zlib/contrib/)
include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)

file(GLOB UTIL_CXX_UNITTEST_WINDOWS_SRC
    "windowsHelper_test.cpp"
    "registryHelper_test.cpp"
    "encodingWindows_test.cpp"
)

file(GLOB UTIL_CXX_UNITTEST_COMMON_SRC
    "archiveHelper_test.cpp"
    "cmdHelper_test.cpp"
    "filesystemHelper_test.cpp"
    "byteArrayHelper_test.cpp"
    "cmdHelper_test.cpp"
    "cacheLRU_test.cpp"
    "hashHelper_test.cpp"
    "mapWrapperSafe_test.cpp"
    "msgDispatcher_test.cpp"
    "pipelineNodes_test.cpp"
    "stringHelper_test.cpp"
    "numericHelper_test.cpp"
    "threadDispatcher_test.cpp"
    "threadSafeQueue_test.cpp"
    "threadSafeMultiQueue_test.cpp"
    "timeHelper_test.cpp"
    "filterMsgDispatcher_test.cpp"
    "loggerHelper_test.cpp"
    "globHelper_test.cpp"
    "socketDBWrapper_test.cpp"
    "wazuhDBQueryBuilder_test.cpp"
    "main.cpp"
)

file(GLOB UTIL_CXX_UNITTEST_LINUX_SRC
    "linuxInfoHelper_test.cpp"
    "socketWrapper_test.cpp"
    "socket_test.cpp"
    "rocksDBSafeQueue_test.cpp"
    "rocksDBQueue_test.cpp"
    "rocksDBSafeQueuePrefix_test.cpp"
    "rocksDBWrapper_test.cpp"
    "threadEventDispatcher_test.cpp"
    "xzHelper_test.cpp"
    "jsonArrayParser_test.cpp"
    "zlibHelper_test.cpp"
    "rsaHelper_test.cpp"
    "evpHelper_test.cpp"
    "socketServer_test.cpp"
)

file(COPY input_files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

link_directories(${SRC_FOLDER}/external/googletest/lib)
link_directories(${SRC_FOLDER}/external/libarchive/.libs/)

if(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
  add_definitions(-DPROMISE_TYPE=PromiseType::SLEEP)
else()
  add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)
endif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_executable(utils_unit_test
      ${UTIL_CXX_UNITTEST_COMMON_SRC}
      ${UTIL_CXX_UNITTEST_WINDOWS_SRC}
      ${UTIL_CXX_UNITTEST_CPP17_SRC}
    )
    add_definitions(-DWIN32=1
                    -D_WIN32_WINNT=0x600)
    target_link_libraries(utils_unit_test
        debug gtestd
        debug gmockd
        optimized gtest
        optimized gmock
        pthread
        crypto
        ssl
        -static-libgcc -static-libstdc++
        ws2_32
        crypt32
    )
else()

    if (APPLE)
      add_executable(utils_unit_test
        ${UTIL_CXX_UNITTEST_COMMON_SRC}
        ${UTIL_CXX_UNITTEST_CPP17_SRC}
      )
    else()
      add_executable(utils_unit_test
        ${UTIL_CXX_UNITTEST_COMMON_SRC}
        ${UTIL_CXX_UNITTEST_LINUX_SRC}
        ${UTIL_CXX_UNITTEST_CPP17_SRC}
      )
    endif(APPLE)

    target_link_libraries(utils_unit_test
        debug gtestd
        debug gmockd
        optimized gtest
        optimized gmock
        rocksdb
        crypto
        dl
        pthread
        rt
        lzma
        z
        minizip
        archive
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_link_libraries(utils_unit_test -fprofile-arcs)
else()
  target_link_libraries(utils_unit_test gcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_test(NAME utils_unit_test
         COMMAND utils_unit_test)
