cmake_minimum_required(VERSION 3.12.4)

project(content_unit_test)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++14")
set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR})

message(STATUS ${CMAKE_SOURCE_DIR})
message(STATUS ${SRC_FOLDER})

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/external/nlohmann/)


file(GLOB CONTENT_CXX_UNITTEST_COMMON_SRC
    "cmdLineHelper_test.cpp"
    "cveFileFetcher_test.cpp"
    "main.cpp"
)

link_directories(${SRC_FOLDER}/external/googletest/lib/)
#link_directories(${SRC_FOLDER}/external/openssl/)

add_executable(content_unit_test
      ${CONTENT_CXX_UNITTEST_COMMON_SRC} "../cveFetchers/cveFileFetcher.cpp"
    )
    
    target_link_libraries(content_unit_test gtest
    )

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_link_libraries(content_unit_test -fprofile-arcs)
else()
  target_link_libraries(content_unit_test gcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_test(NAME content_unit_test
         COMMAND content_unit_test)