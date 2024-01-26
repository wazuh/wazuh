cmake_minimum_required(VERSION 3.12.4)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(keystore)

# enable_testing()

file(GLOB KEYSTORE_SRC
    "src/*.cpp"
    )


if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if (NOT SHARED_MODULES)
    get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

include_directories(include)

include_directories(${SRC_FOLDER}/external/rocksdb/include)

include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/common)

link_directories(${SRC_FOLDER})

add_library(keystore STATIC ${KEYSTORE_SRC})

target_link_libraries(keystore rocksdb wazuhext)

add_executable(wazuh-keystore main.cpp)

target_link_libraries(wazuh-keystore keystore)
