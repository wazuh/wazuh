cmake_minimum_required(VERSION 3.12.4)

project(indexer_connector_component_tests)

file(GLOB SOURCES
        *.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        urlrequest
        debug gtestd
        debug gtest_maind
        optimized gtest
        optimized gtest_main
        indexer_connector
        pthread
)


# PublishBulkErrorLogged and QueueCorruptionTest each construct an IndexerConnector with a real (non-null)
# logFunction to assert on captured log output. loggerHelper.h's GLOBAL_LOG_FUNCTION is a process-wide, "first
# caller wins, no reset" slot with no seam to clear it between tests, so at most one such test can safely share
# a process. Running PublishBulkErrorLogged as its own ctest entry keeps it (and any future test doing the same)
# from silently reading whichever one of them ran first's already-destroyed callback.
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME} --gtest_filter=-IndexerConnectorTest.PublishBulkErrorLogged)
add_test(NAME ${PROJECT_NAME}_PublishBulkErrorLogged
        COMMAND ${PROJECT_NAME} --gtest_filter=IndexerConnectorTest.PublishBulkErrorLogged)
