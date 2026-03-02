## Description

The Office 365 Management Activity API documents `ModifiedProperties`, `Parameters`, and `ExtendedProperties` as `Collection` types containing structured objects, but in practice certain workloads (Exchange, AzureActiveDirectory) return these fields as plain arrays of strings instead. This inconsistency causes Elasticsearch/OpenSearch index mapping conflicts and results in events being silently dropped.

Closes #34521
Closes #28448
Related: #15643
Related: elastic/beats#22780

## Proposed Changes

- Added `wm_office365_normalize_array_of_objects()` in `wm_office365.c` — a generic normalization function that accepts a field name and a NULL-terminated key schema. When a plain string is found in a Collection field that should contain objects, it wraps the string into an object using the provided keys (`keys[0]` receives the string value, remaining keys are set to `""`).
- Applied the function to the three known affected fields before each log entry is sent to the queue: `ModifiedProperties` (`{Name, NewValue, OldValue}`), `Parameters` (`{Name, Value}`), and `ExtendedProperties` (`{Name, Value}`).
- Added 5 unit tests covering: invalid/missing input, well-formed arrays (no-op), all-strings normalization, mixed arrays, and alternative key schemas.

### Results and Evidence

Well-formed events (arrays of objects) pass through with zero modification. Events with plain-string arrays — as reported in the linked issues — are normalized to the documented schema before indexing, preventing the mapping exception.

### Artifacts Affected

- `wazuh-modulesd` (Linux, Windows, macOS)

### Configuration Changes

None.

### Documentation Updates

None — this is a workaround for an undocumented Microsoft API inconsistency, not a user-facing feature.

### Tests Introduced

5 unit tests for `wm_office365_normalize_array_of_objects` in `test_wm_office365.c`:
- `invalid_input` — NULL log, absent field, scalar field (all early-return paths)
- `all_objects` — well-formed array is left untouched
- `all_strings` — all plain strings wrapped into objects (the reported bug case)
- `mixed` — strings wrapped, existing objects preserved
- `name_value_keys` — two-key schema (`Parameters`/`ExtendedProperties`)

## Review Checklist

- [ ] Code changes reviewed
- [ ] Relevant evidence provided
- [ ] Tests cover the new functionality
- [ ] Configuration changes documented
- [ ] Developer documentation reflects the changes
- [ ] Meets requirements and/or definition of done
- [ ] No unresolved dependencies with other issues
