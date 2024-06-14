---
name: Engine decoder issue
about: Propose a new decoder or update an existing one.
title: Engine - <Add/Update> <integration_name> decoder.
labels: feed/engine-ruleset
assignees: ''

---

| Wazuh version |  Integration name  | Integration type | Integration version |
|---------------|--------------------|------------------|---------------------|
|   X.Y.Z-rev   | <integration_name> | new/update       | 1.0.0 - dev         |


## Overview

<!--
  Describe the integration in a few words.
-->


## Checklist before reviewing an integration
<!--
Make sure you meet all the checks before requesting a review.
-->
- [ ] Create a new integration under `engine/ruleset/integrations`
<!--
  ```bash
  engine-integration create <integration_name>
  ```
-->
- [ ] Add and test the agent configuration inside the `<integration_name>/agent/ossec.conf`.
- Events
    - [ ] Identify all events this integration must process.
    - [ ] Create `engine-test` configuration to test the events.
    - [ ] All test events are obfuscated. (i.e. IP, dates)
- Develop neccesary decoders, for each decoder ensure:
    - [ ] Regex was used only when strictly necessary.
    - [ ] The decoder does not depend on the evaluation of sibling decoders (It does not have to be run with another decoder in a specific order since the check stage is exhaustive).
    - [ ] All fields mapped are documented in the integration's sheet.
    <!--
    under file `<integration_name>/decoder_fields` in https://drive.google.com/drive/folders/1OYbSX65hIis8FKQmw75NseKoBoXv-neb?usp=sharing
    -->
    - [ ] Is in the `wazuh` namespace.
    - Added test for all events:
        - [ ] `input` added
        - [ ] `expected` added
        - [ ] `engine-test.conf` added
- Testing
    - [ ] `./test/health_test/run.py` runs without errors.
    - [ ] The events in the dashbord are displayed correctly.
    - [ ] There are no warnings or errors on Filebeta logs when indexing events.
        <!--
            Execute before running the test:
            - tail -f `/var/log/filebeat/filebeat`
        -->
- Documentation
    - [ ] Title, Overview, Compatibility, Configuration, event module/dataset added in `documentation.yml`
    - [ ] Add entry to the `changelog.yml`
    - [ ] The `engine-integration generate-doc` tool generated the `readme.MD` correctly
