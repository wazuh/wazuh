## Description

Windows Event ID 7040 (Service Start Type Change) was missing the `win.system.securityUserID` field in Wazuh alerts, even though the raw XML sent by the agent contained the `<Security UserID='...'/>` element with the correct SID. This prevented identifying which user performed the service configuration change.

## Proposed Changes

In `DecodeWinevt()`, the XML parser stores attribute names in `attributes[]` and attribute values in `values[]`. For the `<Security UserID='S-1-5-...'/>` element, `attributes[0]` = `"UserID"` and `values[0]` = the actual SID.

Two handlers in the `<System>` block were incorrectly checking `values[0]` against the string `"UserID"` instead of `attributes[0]`. Since `values[0]` holds a SID (e.g. `S-1-5-21-...`), the condition always evaluated to false and the field was silently dropped.

- **`Security` element** (`winevtchannel.c`): caused `win.system.securityUserID` to never be populated — the user who triggered the event was always lost.
- **`Channel` element** (`winevtchannel.c`): same logic error, though dead code in practice since `<Channel>` has no attributes in real Windows events.

Both checks were changed from `!strcmp(child_attr[p]->values[0], "UserID")` to `!strcmp(child_attr[p]->attributes[0], "UserID")`, consistent with how `TimeCreated`, `Execution`, and `Provider` are handled in the same function.

Unit tests for both handlers were updated to use realistic data (`attributes[0]` = `"UserID"`, `values[0]` = `"S-1-5-18"`), and the TODO comment on the Channel test was removed.

### Results and Evidence

Before fix — `win.system.securityUserID` absent despite SID present in raw XML:

```sql
2026 Apr 27 13:18:18 (win2022) any->EventChannel {"win":{"system":{"providerName":"Service Control Manager","eventID":"7040","systemTime":"2026-04-27T13:18:17.6066123Z","channel":"System","computer":"win2022","severityValue":"INFORMATION","message":"\"The start type of the Print Spooler service was changed from demand start to auto start.\""},"eventdata":{"param1":"Print Spooler","param2":"demand start","param3":"auto start","param4":"Spooler"}}}
```

After fix — `securityUserID` correctly populated:

```sql
2026 Apr 27 14:28:14 (win2022) any->EventChannel {"win":{"system":{"providerName":"Service Control Manager","eventID":"7040","systemTime":"2026-04-27T14:28:13.8980518Z","channel":"System","computer":"win2022","severityValue":"INFORMATION","securityUserID":"S-1-5-21-2773635809-332327098-1920082839-1000","message":"\"The start type of the Print Spooler service was changed from auto start to demand start.\""},"eventdata":{"param1":"Print Spooler","param2":"auto start","param3":"demand start","param4":"Spooler"}}}
```

### Artifacts Affected

- `wazuh-analysisd` (Linux manager)

### Configuration Changes

None.

### Documentation Updates

None.

### Tests Introduced

Updated existing unit test `test_winevt_dec_systemNode_ok` in `src/unit_tests/analysisd/test_decoder_winevtchannel.c`:
- `Channel` node: attribute name corrected to `"UserID"`, value to `"S-1-5-18"`, expected JSON value updated accordingly, TODO removed.
- `Security` node: same corrections applied.

## Review Checklist

- [ ] Code changes reviewed
- [ ] Relevant evidence provided
- [ ] Tests cover the new functionality
- [ ] Configuration changes documented
- [ ] Developer documentation reflects the changes
- [ ] Meets requirements and/or definition of done
- [ ] No unresolved dependencies with other issues
