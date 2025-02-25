cmake_minimum_required(VERSION 3.12.4)

project(flatbuffer_tool)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../../ ABSOLUTE)
endif()

# Include directories
include_directories(include)
include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/external/flatbuffers/include)
include_directories(${SRC_FOLDER}/external/nlohmann)

# Link directories
link_directories(${SRC_FOLDER}/external/flatbuffers/build)

file(GLOB FLATBUFFERS_TOOL_SRC
    "src/*.cpp"
    )

add_executable(flatbuffer_tool ${FLATBUFFERS_TOOL_SRC})

target_link_libraries(flatbuffer_tool flatbuffers)

add_subdirectory(schemas)
