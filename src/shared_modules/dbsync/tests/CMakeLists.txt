project(dbsync_unit_test)

# All dbsync tests will depend on this target
add_custom_target(dbsync_unit_test)

# Adding the dbsync tests to the general unit_test target
add_dependencies(${ALL_UNIT_TEST_TARGET} dbsync_unit_test)

# Setting options for all the dbsync tests
add_compile_options(-O0 -g --coverage)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    link_libraries(-fprofile-arcs)
else()
    link_libraries(-lgcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(sqlite)
add_subdirectory(interface)
add_subdirectory(pipelineFactory)
add_subdirectory(dbengine)
