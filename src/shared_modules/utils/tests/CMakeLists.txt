project(utils_unit_test)

# Adding the utils tests to the general unit_test target
add_dependencies(${ALL_UNIT_TEST_TARGET} utils_unit_test)

# Setting options for all the rsync tests
add_compile_options(-O0 -g --coverage)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    link_libraries(-fprofile-arcs)
else()
    link_libraries(-lgcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

file(GLOB UTIL_CXX_UNITTEST_WINDOWS_SRC
    "windowsHelper_test.cpp"
    "registryHelper_test.cpp"
    "encodingWindows_test.cpp"
)

file(GLOB UTIL_CXX_UNITTEST_COMMON_SRC
    "cmdHelper_test.cpp"
    "filesystemHelper_test.cpp"
    "byteArrayHelper_test.cpp"
    "cmdHelper_test.cpp"
    "hashHelper_test.cpp"
    "mapWrapperSafe_test.cpp"
    "msgDispatcher_test.cpp"
    "pipelineNodes_test.cpp"
    "stringHelper_test.cpp"
    "threadDispatcher_test.cpp"
    "threadSafeQueue_test.cpp"
    "timeHelper_test.cpp"
    "main.cpp"
)

file(GLOB UTIL_CXX_UNITTEST_LINUX_SRC
    "linuxInfoHelper_test.cpp"
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_executable(utils_unit_test
        ${UTIL_CXX_UNITTEST_COMMON_SRC}
        ${UTIL_CXX_UNITTEST_WINDOWS_SRC}
    )
    add_definitions(-DWIN32=1
        -D_WIN32_WINNT=0x600)
    target_link_libraries(utils_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        crypto
        ssl
        -static-libgcc -static-libstdc++
        ws2_32
        crypt32
    )
else()
    add_executable(utils_unit_test
        ${UTIL_CXX_UNITTEST_COMMON_SRC}
        ${UTIL_CXX_UNITTEST_LINUX_SRC}
    )
    target_link_libraries(utils_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        crypto
        dl
        pthread
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME utils_unit_test
    COMMAND utils_unit_test)
