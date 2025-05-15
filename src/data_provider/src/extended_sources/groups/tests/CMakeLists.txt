get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../../../ ABSOLUTE)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

if(LINUX)
    set(TEST_SRC test_user_groups_linux.cpp)
elseif(WIN32)
    set(TEST_SRC test_user_groups_windows.cpp)
elseif(DARWIN)
    set(TEST_SRC test_user_groups_darwin.cpp)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

add_executable(test_user_groups ${TEST_SRC})

target_link_libraries(test_user_groups
    user_groups
    gtestd
    gmockd
    gtest_maind
    gmock_maind
)

add_test(NAME UserGroupsTests COMMAND test_user_groups)
