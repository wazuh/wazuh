cmake_minimum_required(VERSION 3.12.4)

project(syscollectorfb_unit_test)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB SYSCOLLECTOR_IMP_UNIT_TEST_SRC
    "*.cpp")

add_definitions(-DWAZUH_UNIT_TESTING)

add_executable(syscollectorfb_unit_test ${SYSCOLLECTOR_IMP_UNIT_TEST_SRC})
target_compile_definitions(syscollectorfb_unit_test PUBLIC SCHEMA_ROOT_PATH="${SRC_FOLDER}/wazuh_modules/syscollector/schemas/")

target_link_libraries(syscollectorfb_unit_test
        debug gtestd
        optimized gtest
        flatbuffers
    )

add_test(NAME syscollectorfb_unit_test
         COMMAND syscollectorfb_unit_test)
