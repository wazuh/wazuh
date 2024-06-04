cmake_minimum_required(VERSION 3.12.4)

project(flatbuffer_tool)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(include)
include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/external/flatbuffers/include)

# Link directories
link_directories(${SRC_FOLDER}/external/flatbuffers/build)

file(GLOB FLATBUFFERS_TOOL_SRC
    "src/*.cpp"
    )

add_executable(flatbuffer_tool ${FLATBUFFERS_TOOL_SRC})

target_link_libraries(flatbuffer_tool flatbuffers)

