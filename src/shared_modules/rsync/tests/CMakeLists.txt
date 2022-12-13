project(rsync_unit_tests)

include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)

# All rsync tests will depend on this target
add_custom_target(rsync_unit_tests)

# Adding the rsync tests to the general unit_test target
add_dependencies(${ALL_UNIT_TEST_TARGET} rsync_unit_tests)

# Setting options for all the rsync tests
add_compile_options(-O0 -g --coverage)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    link_libraries(-fprofile-arcs)
else()
    link_libraries(-lgcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(interface)
add_subdirectory(implementation)
