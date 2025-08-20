# Insert RSYNC Services Test

This test verifies the insertion of service data using RSYNC operations.

## Test Data

The test includes various service configurations:
- Complete service data with all fields
- Minimal service data with only name
- Empty/null field handling
- Different service states (running, stopped)
- Different service types (simple, forking)

## Expected Behavior

- Services with complete data are indexed with all available fields
- Services with minimal data are indexed with only the available fields
- Empty strings and null values are handled appropriately
- Services without a name are filtered out
