cmake_minimum_required(VERSION 3.12.4)
set(CMAKE_CXX_STANDARD 17)

project(keystore)

# enable_testing()

file(GLOB KEYSTORE_SRC
    "src/*.cpp"
    )


if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(include/)
include_directories(../utils/)
include_directories(${SRC_FOLDER}/external/rocksdb/include)

add_library(keystore STATIC
    ${KEYSTORE_SRC}
    )

target_link_libraries(keystore rocksdb)

add_executable(wazuh-keystore main.cpp)
target_link_libraries(wazuh-keystore keystore)
