cmake_minimum_required(VERSION 3.12.4)

project(syscollectorflatbuffers_unit_test)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB SYSCOLLECTOR_FLATBUFFERS_UNIT_TEST_SRC
    "*.cpp")

add_definitions(-DWAZUH_UNIT_TESTING)

add_executable(${PROJECT_NAME}
    ${SYSCOLLECTOR_FLATBUFFERS_UNIT_TEST_SRC}
)
target_compile_definitions(syscollectorfb_unit_test PUBLIC SCHEMA_ROOT_PATH="${SRC_FOLDER}/wazuh_modules/syscollector/schemas/")

target_link_libraries(${PROJECT_NAME}
        debug gtestd
        optimized gtest
        flatbuffers
)

add_test(NAME ${PROJECT_NAME}
    COMMAND ${PROJECT_NAME})
