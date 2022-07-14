cmake_minimum_required(VERSION 3.12.4)
project(content_migration)

enable_testing()

include_directories(src/)
include_directories(src/NVD/)
include_directories(src/cveFetchers/)

link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib/)
file(GLOB CONTENT_MIGRATOR_SRC src/*.cpp src/NVD/*.cpp src/cveFetchers/*.cpp)

add_subdirectory(src/tests)

add_executable(content_migration
    ${CONTENT_MIGRATOR_SRC})

target_link_libraries(content_migration ssl crypto)

