get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

set(TEST_SRC "main.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND TEST_SRC test_user_groups_windows.cpp)
else()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND TEST_SRC test_user_groups_linux.cpp)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        list(APPEND TEST_SRC test_user_groups_darwin.cpp)
    endif()
endif()

add_executable(extended_sources_user_groups_unit_test ${TEST_SRC})

target_link_libraries(extended_sources_user_groups_unit_test
    groups
    gtestd
    gmockd
    gtest_maind
    gmock_maind
)

add_test(NAME UserGroupsTests COMMAND extended_sources_user_groups_unit_test)
