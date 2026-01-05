cmake_minimum_required(VERSION 3.12.4)

project(schema_validator_unit_test)

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

include_directories(${CMAKE_SOURCE_DIR}/../../../)
include_directories(${SRC_FOLDER}/external)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${CMAKE_SOURCE_DIR}/include)

link_directories(${CMAKE_BINARY_DIR}/lib)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

file(GLOB VALIDATOR_UNIT_TEST_SRC
    "*.cpp")

file(GLOB VALIDATOR_SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(schema_validator_unit_test
    ${VALIDATOR_UNIT_TEST_SRC}
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(schema_validator_unit_test
        schema_validator
        debug gtestd
        debug gtest_maind
        optimized gtest
        optimized gtest_main
        pthread
        ws2_32
        crypt32
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(schema_validator_unit_test
        schema_validator
        debug gtestd
        debug gtest_maind
        optimized gtest
        optimized gtest_main
        pthread
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME schema_validator_unit_test
         COMMAND schema_validator_unit_test)
