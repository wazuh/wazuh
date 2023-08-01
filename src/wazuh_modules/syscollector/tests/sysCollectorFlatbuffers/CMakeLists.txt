cmake_minimum_required(VERSION 3.12.4)

project(syscollectorfb_unit_test)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB SYSCOLLECTOR_IMP_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSCOLLECTOR_SCHEMAS_UNIT_TEST
    "${SRC_FOLDER}/wazuh_modules/syscollector/schemas/*.fbs")

add_definitions(-DWAZUH_UNIT_TESTING)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # === flatbuffers
    set(FLATBUFFERS_SRC_DIR "${SRC_FOLDER}/external/flatbuffers")
    set(FLATBUFFERS_BINARY_DIR "${SRC_FOLDER}/external/flatbuffers/build")
    set(FLATBUFFERS_INCLUDE_DIR "${SRC_FOLDER}/external/flatbuffers/include")

    # set flatbuffers CMake options
    set(FLATBUFFERS_BUILD_FLATLIB ON CACHE BOOL "Enable the build of the flatbuffers library")
    set(FLATBUFFERS_BUILD_SHAREDLIB OFF CACHE BOOL "Disable the build of the flatbuffers shared library")
    set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "Skip flatbuffers tests")

    add_subdirectory(${FLATBUFFERS_SRC_DIR} "${FLATBUFFERS_BINARY_DIR}")

    add_library(_flatbuffers INTERFACE)
    target_link_libraries(_flatbuffers INTERFACE flatbuffers)
    target_include_directories(_flatbuffers INTERFACE ${FLATBUFFERS_INCLUDE_DIR})

endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

# add_custom_command does not create a new target. You have to define targets explicitly
# by add_executable, add_library or add_custom_target in order to make them visible to make
# For this reason, add_custom_target adds a target with the given name that executes the given commands.
# The target has no output file and is always considered out of date even if the commands try to create a
# file with the name of the target.
add_custom_target(compile_schemas)
foreach(FILE ${SYSCOLLECTOR_SCHEMAS_UNIT_TEST})
add_custom_command(
    TARGET compile_schemas
    COMMAND ${SRC_FOLDER}/external/flatbuffers/build/flatc ${TEST_FILE}
    ARGS --gen-name-strings --force-empty --cpp
    ARGS --gen-compare --cpp-str-flex-ctor
    ARGS -o "${CMAKE_CURRENT_SOURCE_DIR}/" "${FILE}"
    COMMENT "Building C++ header for ${FILE}"
    DEPENDS ${FILE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endforeach(FILE)

add_definitions(-DWAZUH_UNIT_TESTING)

add_executable(syscollectorfb_unit_test ${SYSCOLLECTOR_IMP_UNIT_TEST_SRC})
add_dependencies(${PROJECT_NAME} compile_schemas) #Add a dependency between top-level targets.

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(syscollectorfb_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        cjson
        sqlite3
        crypto
        ws2_32
        ssl
        crypt32
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(syscollectorfb_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        sqlite3
        cjson
        crypto
        dl
        _flatbuffers
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME syscollectorfb_unit_test
         COMMAND syscollectorfb_unit_test)
