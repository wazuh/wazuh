---
name: 'Test: Monitord'
about: Test suite for Monitord.

---

# Monitord test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Logs

- [ ] Check the daily rotation of logs and their checksums.
- [ ] Rotate internal logs by size with the internal options available.
- [ ] Rotate alerts and archives (first day, no previous logs).
- [ ] Rotate alerts and archives (second day, having previous logs).
- [ ] Set the JSON output for every logs if possible (archives, internal logs, etc).
- [ ] Check in JSON log every alert content all default fields:
  - timestamp.
  - rules-id.
  - rule level.
  - rule group.
  - agent id.
  - agent name.
  - agent ip.
  - manager.
  - full log.
  - location.
  - manager name.
  - decoders field.
  - data.
