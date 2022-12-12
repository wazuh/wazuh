project(unit_tests)

include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)

add_subdirectory(interface)
add_subdirectory(implementation)
