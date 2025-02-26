## Description

This test verifies that all the data of an agent is removed from all indexes when it's deleted.

## Steps

- 1_delta_inserted.json: inserts OS data.
- 2_delta_inserted.json: inserts a package.
- 3_delta_inserted.json: inserts registry data.
- 4_rsync_states.json: inserts a file.
- 5.json: an agent removal event.

## Expected

All indexes must be empty.
