get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

if(FSANITIZE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_CXX_FLAGS_DEBUG " -g --coverage -fsanitize=address,leak,undefined")
endif()

include_directories(
    ${SRC_FOLDER}/external/googletest/googletest/include/
    ${SRC_FOLDER}/external/googletest/googlemock/include/
    ${SRC_FOLDER}/wazuh_modules/agent_info/agent_info_impl/src
    ${SRC_FOLDER}/wazuh_modules/agent_info/agent_info_impl/include
    ${SRC_FOLDER}/wazuh_modules/agent_info/agent_info_impl/tests
    ${SRC_FOLDER}/wazuh_modules/agent_info/agent_info_impl/tests/mocks
    ${SRC_FOLDER}/shared_modules/dbsync/tests/mocks
    ${SRC_FOLDER}/shared_modules/file_helper/filesystem/tests/mocks
    ${SRC_FOLDER}/shared_modules/file_helper/file_io/tests/mocks
    ${SRC_FOLDER}/shared_modules/utils/tests/mocks
    ${SRC_FOLDER}/data_provider/tests/mocks
)

link_directories(${SRC_FOLDER}/external/googletest/lib/)
link_libraries(
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
)

add_executable(agent_info_impl_unit_test agent_info_impl_test.cpp)
target_link_libraries(agent_info_impl_unit_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoImplTest COMMAND agent_info_impl_unit_test)
