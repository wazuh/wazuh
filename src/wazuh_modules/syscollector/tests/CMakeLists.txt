project(syscollector_unit_test)

# All syscollector tests will depend on this target
add_custom_target(${PROJECT_NAME})

# Adding the syscollector tests to the general unit_test target
add_dependencies(${ALL_UNIT_TEST_TARGET} ${PROJECT_NAME})

# Setting options for all the syscollector tests
add_compile_options(-O0 -g --coverage)
add_definitions(-DWAZUH_UNIT_TESTING)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    link_libraries(-fprofile-arcs)
else()
    link_libraries(-lgcov)
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(sysCollectorImp)
add_subdirectory(sysNormalizer)
