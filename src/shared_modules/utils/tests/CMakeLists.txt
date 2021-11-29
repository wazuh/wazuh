cmake_minimum_required(VERSION 3.12.4)

project(utils_unit_test)

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../../ ABSOLUTE)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++14")
set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${SRC_FOLDER}/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/nlohmann/)

file(GLOB UTIL_CXX_UNITTEST_SRC
    "*.cpp")

link_directories(${SRC_FOLDER}/external/googletest/lib/)
link_directories(${SRC_FOLDER}/external/openssl/)

add_executable(utils_unit_test
    ${UTIL_CXX_UNITTEST_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_definitions(-DWIN32=1
                    -D_WIN32_WINNT=0x600)
    target_link_libraries(utils_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtestd
        optimized gmockd
        optimized gtest_maind
        optimized gmock_maind
        pthread
        crypto
        ssl
        -static-libgcc -static-libstdc++
        ws2_32
        crypt32
    )
else()
    target_link_libraries(utils_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtestd
        optimized gmockd
        optimized gtest_maind
        optimized gmock_maind
        crypto
        dl
        pthread
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_link_libraries(utils_unit_test -fprofile-arcs)
else()
  target_link_libraries(utils_unit_test gcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_test(NAME utils_unit_test
         COMMAND utils_unit_test)