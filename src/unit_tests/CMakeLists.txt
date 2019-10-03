cmake_minimum_required(VERSION 3.13)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/../headers)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/../)

FIND_LIBRARY(WAZUHLIB NAMES libwazuh.a HINTS "${CMAKE_SOURCE_DIR}/../")
FIND_LIBRARY(WAZUHEXT NAMES libwazuhext.so HINTS "${CMAKE_SOURCE_DIR}/../")

SET_SOURCE_FILES_PROPERTIES(
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
)

ADD_COMPILE_OPTIONS(-ggdb)

# Tests list and flags
LIST(APPEND tests_names "test_file_op")
LIST(APPEND tests_flags "-Wl,--wrap,merror -Wl,--wrap,isChroot -Wl,--wrap,chmod -Wl,--wrap,File_DateofChange -Wl,--wrap,getpid -Wl,--wrap,unlink")

LIST(APPEND tests_names "test_integrity_op")
LIST(APPEND tests_flags " ")

LIST(APPEND tests_names "test_rbtree_op")
LIST(APPEND tests_flags " ")

# Declare all tests targets
LIST(LENGTH tests_names count)
MATH(EXPR count "${count} - 1")
FOREACH(i RANGE ${count})
    LIST(GET tests_names ${i} test_name)
    LIST(GET tests_flags ${i} test_flags)

    ADD_EXECUTABLE(${test_name} ${test_name}.c)

    TARGET_LINK_LIBRARIES(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        -lcmocka
        -fprofile-arcs
        -ftest-coverage
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
