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

# Agent Info Basic Tests (constructor, start/stop, lifecycle)
add_executable(agent_info_basic_test agent_info_basic_test.cpp)
target_link_libraries(agent_info_basic_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoBasicTest COMMAND agent_info_basic_test)

# Agent Info Metadata Tests (client.keys, merged.mg, OS info)
add_executable(agent_info_metadata_test agent_info_metadata_test.cpp)
target_link_libraries(agent_info_metadata_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoMetadataTest COMMAND agent_info_metadata_test)

# Agent Info DBSync Integration Tests (callbacks, SQL operations)
add_executable(agent_info_dbsync_test agent_info_dbsync_test.cpp)
target_link_libraries(agent_info_dbsync_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoDBSyncTest COMMAND agent_info_dbsync_test)

# Agent Info Event Processing Tests (INSERTED/MODIFIED/DELETED events)
add_executable(agent_info_events_test agent_info_events_test.cpp)
target_link_libraries(agent_info_events_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoEventsTest COMMAND agent_info_events_test)

# Agent Info Utility Functions Tests (checksums, hash IDs, ECS formatting)
add_executable(agent_info_utils_test agent_info_utils_test.cpp)
target_link_libraries(agent_info_utils_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoUtilsTest COMMAND agent_info_utils_test)

# Agent Info Logging Tests (log levels, error handling)
add_executable(agent_info_logging_test agent_info_logging_test.cpp)
target_link_libraries(agent_info_logging_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoLoggingTest COMMAND agent_info_logging_test)

# Agent Info Integration Tests (end-to-end with real DBSync)
add_executable(agent_info_integration_test agent_info_integration_test.cpp)
target_link_libraries(agent_info_integration_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoIntegrationTest COMMAND agent_info_integration_test)

# Agent Info Coordination Tests (module coordination, query handling, resetSyncFlag)
add_executable(agent_info_coordination_test agent_info_coordination_test.cpp)
target_link_libraries(agent_info_coordination_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoCoordinationTest COMMAND agent_info_coordination_test)

# Agent Info Successful Coordination Tests (complete coordination flow)
add_executable(agent_info_successful_coordination_test agent_info_successful_coordination_test.cpp)
target_link_libraries(agent_info_successful_coordination_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoSuccessfulCoordinationTest COMMAND agent_info_successful_coordination_test)

# Agent Info Integrity Check Tests (periodic integrity checks, CHECK modes)
add_executable(agent_info_integrity_test agent_info_integrity_test.cpp)
target_link_libraries(agent_info_integrity_test PRIVATE AGENT_INFO_IMPL)
add_test(NAME AgentInfoIntegrityTest COMMAND agent_info_integrity_test)
