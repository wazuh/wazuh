/**
 * @file agent_info_impl_test.cpp
 * @brief AgentInfoImpl test suite - reorganized into separate files
 *
 * This test file has been reorganized into separate files for better maintainability:
 *
 * - agent_info_basic_test.cpp: Basic functionality tests (constructor, start/stop, lifecycle)
 * - agent_info_metadata_test.cpp: Metadata population tests (client.keys, merged.mg, OS info)
 * - agent_info_dbsync_test.cpp: DBSync integration tests (callbacks, SQL operations)
 * - agent_info_events_test.cpp: Event processing tests (INSERTED/MODIFIED/DELETED events)
 * - agent_info_utils_test.cpp: Helper function tests (checksums, hash IDs, ECS formatting)
 * - agent_info_logging_test.cpp: Logging functionality tests (log levels, error handling)
 * - agent_info_integration_test.cpp: End-to-end integration tests with real DBSync
 *
 * Each file focuses on a specific aspect of the AgentInfoImpl functionality,
 * making the tests easier to understand, maintain, and extend.
 */

// This file is intentionally empty as all tests have been moved to specific test files.
// If you need to add new tests, please add them to the appropriate specialized test file
// or create a new file following the naming convention: agent_info_<functionality>_test.cpp
