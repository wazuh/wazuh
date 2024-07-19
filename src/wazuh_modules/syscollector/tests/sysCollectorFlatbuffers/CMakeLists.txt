cmake_minimum_required(VERSION 3.12.4)

project(syscollectorflatbuffers_unit_test)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB FLATBUFFER_SCHEMAS
  "${CMAKE_SOURCE_DIR}/../../shared_modules/utils/flatbuffers/schemas/common/*"
  "${CMAKE_SOURCE_DIR}/../../shared_modules/utils/flatbuffers/schemas/syscollectorDeltas/*"
)
file(COPY ${FLATBUFFER_SCHEMAS} DESTINATION ${CMAKE_SOURCE_DIR}/build/bin/)

file(GLOB SYSCOLLECTOR_FLATBUFFERS_UNIT_TEST_SRC
    "*.cpp")

add_definitions(-DWAZUH_UNIT_TESTING)

add_executable(${PROJECT_NAME}
    ${SYSCOLLECTOR_FLATBUFFERS_UNIT_TEST_SRC}
)
target_compile_definitions(${PROJECT_NAME} PUBLIC SCHEMA_ROOT_PATH="${SRC_FOLDER}/shared_modules/utils/flatbuffers/schemas/syscollectorRsync/")

target_link_libraries(${PROJECT_NAME}
        debug gtestd
        optimized gtest
        flatbuffers
)

add_test(NAME ${PROJECT_NAME}
    COMMAND ${PROJECT_NAME})

add_custom_target(set_path
    COMMAND sed -i "s/..common//" ${CMAKE_SOURCE_DIR}/build/bin/syscollector_deltas.fbs
    COMMENT "Set common flatbuffers schema path"
)
add_dependencies(${PROJECT_NAME} set_path)
