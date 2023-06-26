cmake_minimum_required(VERSION 3.5)

project(ProjectName)

# Add your source files
set(SOURCE_FILES
    src/add.c
)

# Create the mylib library
add_library(mylib ${SOURCE_FILES})

# Add your header files directory
include_directories(src)

# Add your test source files
set(TEST_SOURCE_FILES
    test/test_add.c
)

# Find cmocka
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/../test/cmocka/include)
FIND_LIBRARY(CMOCKA_LIBRARY cmocka HINTS ../../test/cmocka/build/src)

# List of tests and their flags
LIST(APPEND tests_names "test_add")
LIST(APPEND tests_flags "-Wl,--wrap,add")


# Declare all tests targets
LIST(LENGTH tests_names count)
MATH(EXPR count "${count} - 1")
FOREACH(i RANGE ${count})
    LIST(GET tests_names ${i} test_name)
    LIST(GET tests_flags ${i} test_flags)
    ADD_EXECUTABLE(${test_name} test/${test_name}.c)
    TARGET_LINK_LIBRARIES(
        ${test_name}
        ${CMOCKA_LIBRARY}
        -fprofile-arcs
        mylib
    )
    IF(test_flags STREQUAL " ")
    ELSE()
        TARGET_LINK_LIBRARIES(
            ${test_name}
            ${test_flags}
        )
    ENDIF()
    ADD_TEST(${test_name} ${test_name})
ENDFOREACH()

execute_process(
    COMMAND cmocka-config --version
    OUTPUT_VARIABLE CMOCKA_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

