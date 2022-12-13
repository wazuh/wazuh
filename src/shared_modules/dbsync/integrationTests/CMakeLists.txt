project(dbsync_integration_tests)

# All dbsync integration tests will depend on this target
add_custom_target(dbsync_integration_tests)

# Adding the dbsync integration tests to the general unit_test target
add_dependencies(${ALL_UNIT_TEST_TARGET} dbsync_integration_tests)

# Setting options for all the dbsync integration tests
add_compile_options(-O0 -g --coverage)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    link_libraries(-fprofile-arcs)
else()
    link_libraries(-lgcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(fim)
