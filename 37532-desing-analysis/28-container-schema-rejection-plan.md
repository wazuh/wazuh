# Container state-template patch

Session: `01a1b164-78ba-75d3-b29c-0ad9087a192f`.

## Defect and verified scope

All 17 downloaded state templates originally had `template.mappings.dynamic: strict` and no `container` property. `src/shared_modules/schema_validator/CMakeLists.txt` embeds these JSON files into generated schemaResources.cpp and libschema_validator.so. The strict extra-field loop in schemaValidator.cpp rejects non-null unmapped fields with `Field not allowed in strict mode` (unmapped nulls are accepted).

The named `37532-validation-report.md` is not present here. The available `37532-desing-analysis/22-container-e2e-validation-report.md` §22.7 records 702 discards and zero surviving container inventory rows. Verified deletion paths at current source locations: syscollectorImp.cpp:8609 (`deleteFailedItemsFromDB`, calling deleteRows); syscheckd/src/file/file.c:1267 and :1587 call `cleanup_failed_fim_files`; syscheckd/src/run_check.c:623 deletes the rows. These functions are unchanged.

Read baseline_rows.hpp: exactly the twelve requested Build*Json producer classes are declared, plus their dbsync equivalents. No container registry, hotfix, browser-extension, or SCA producer is declared. Changed only fim-files.json and inventory-{processes,ports,users,groups,packages,system,interfaces,networks,protocols,services,hardware}.json under src/external/indexer-plugins/. The other five templates remain byte-identical.

Read ContainerBlock(), KubernetesBlock(), StampContainerContext(), and BuildContainerContextJson() in baseline_rows.cpp, and the context structs. The mapping follows the actual emitted shape, including optional Kubernetes fields and integer restart_count. Docker contexts omit kubernetes. Subtle source finding: KubernetesBlock returns an optional object even if an existing KubernetesContext has all fields empty; the source does not itself guarantee a nonempty Kubernetes block. No producer behavior changed.

src/Makefile:550 onward and the state download rule at :751 onward confirm raw GitHub downloads using GIT_REFS_LIST and the upstream states path. Neither Makefile nor download behavior changed. Pristine local copies were saved before editing; upstream byte identity was supplied in the task, not independently re-fetched.

## Mapping decisions

- Labels and Kubernetes annotations use `flat_object`. OpenSearch introduced it in 2.7; Wazuh's current compatibility page says its 5.0+ indexer uses OpenSearch 3.6.0. This avoids dynamic mapping growth for arbitrary keys, including dotted/slashed Kubernetes keys and manifest-valued annotation strings. It supports exact-match queries with limitations; dot-path subfield aggregations are unsupported and some searches can be expensive. Sources: [Wazuh compatibility](https://wazuh.github.io/wazuh-indexer-plugins/ref/compatibility.html), [OpenSearch flat_object documentation](https://docs.opensearch.org/latest/mappings/supported-field-types/flat-object/). No dynamic:true or enabled:false workaround.
- Network, OCI mounts, and owner references use plain object `properties`, permitting object arrays with flattened cross-object matching. No requirement here needs correlated per-element queries; nested documents would add indexing/storage/query cost. Queries combining fields can match different elements; correlated querying would require a separate mapping decision.
- All strings outside the arbitrary maps are keyword with ignore_above:4096, except network.ip, which is typed ip. restart_count is integer; mount ro is boolean. Properties are alphabetical, with two-space indentation and trailing newline. Strictness is unchanged everywhere.
- Added all bounded container keyword leaves to query.default_field, alphabetically: identity, image, runtime, namespace/pod/node/owner references, network names, mount source/destination. This makes ordinary dashboard searches find container identity and names. Excluded flat metadata maps (large arbitrary annotation values), IP, integer, and boolean fields to avoid broad default queries against incompatible types. Those remain available for explicit field queries.
- ECS divergence is intentional in this patch: engine-schema.json declares image.tag and image.hash.all; emitted image.digest is mapped as emitted. restart_count, oci_mounts, and kubernetes also diverge from that declared ECS set. Additionally the engine declares container.network.egress.bytes and ingress.bytes as metrics under network, whereas the agent emits network as an array of {name,ip}. These shapes cannot share one field contract if the schemas converge. Resolve naming/contracts separately with database and wire implications; no emitted names changed.

## Bounded validator fix

Only validateObject's mapped-object handling changed: arrays recurse into validateObject per non-null element with paths such as address[1].city; null elements are skipped. Scalars still fail the existing object check. No changes to validateField, schema loading, or strict extra-field handling. Five focused fixture tests cover valid object arrays including a null element, bad leaf type at index 1, a scalar element, empty arrays, and a null field.

Finding left unchanged: validateField has no final else, so unknown types including flat_object silently pass. Labels/annotations currently pass through that gap, without a C++ change. This is not a deliberate typed-validation mechanism; a misspelled type also passes. Typed array members use real properties and recognized leaf types.

## Deployment work outside this patch

1. Land the template patch in wazuh-indexer-plugins at the ref used by the build. Land the bounded validator fix/tests in this Wazuh repository. Rebuild/reinstall the agent so the patched templates are embedded; rebuild any manager components using this library as applicable. A template-only indexer change does not repair the old agent validator or recover deleted rows.
2. Build/deploy the indexer setup plugin with the updated resources and run its template installation/update path. Confirm installed templates with the indexer API. A plugin binary update alone must not be assumed to replace templates automatically; that upgrade path was not exercised here.
3. Updated index templates affect newly created indices only. Existing indices need an explicit additive PUT _mapping of the container subtree and a settings update for index.query.default_field, or a rollover/new index that receives the updated template (where the deployment supports rollover). Reapplying the index template alone does not update existing index mappings/settings. No rollover is inherently necessary for this additive mapping if existing indices are updated directly. Existing conflicting container mappings require separate migration/reindex planning.
4. Refresh the dashboard index pattern/data view field list after mappings exist so discoverable new fields appear. Flat-object arbitrary keys are not independent mapped fields and should not be expected to appear individually or support normal keyword aggregations. Verify real dashboard search behavior after deployment.
5. Trigger container baseline/resynchronization to recreate rows previously deleted on schema rejection, then verify indexing and dashboard visibility end to end. This patch does not restore historical data or prove there are no independent delivery defects.

No live indexer/dashboard, full agent build, plugin installation, rollover, or baseline replay was run. Compatibility is documented, not an ingestion test against the target cluster. No actual wazuh-indexer-plugins checkout is available here: `git apply --check` against that repository could not be run. A synthetic pristine tree check below verifies paths and patch reconstruction only.

## Validation commands and verbatim results

Built the entire standalone validator library, test tool, and unit test targets with the existing tests/CMakeLists.txt via a temporary harness in /tmp/37532-container-validation/harness. The harness supplies SRC_FOLDER, WAZUH_MAIN_PROJECT, UNIT_TEST, enable_testing, and the normal GCC coverage helper, avoiding unrelated full-agent targets. Commands:

```sh
cmake -S /tmp/37532-container-validation/harness -B /tmp/37532-container-validation/build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/37532-container-validation/build -j2
ctest --test-dir /tmp/37532-container-validation/build --output-on-failure
/tmp/37532-container-validation/build/bin/schema_validator_test_tool
/tmp/37532-container-validation/build/bin/schema_validator_unit_test
```

Verbatim CTest output:

```text
Test project /tmp/37532-container-validation/build
    Start 1: schema_validator_unit_test
1/1 Test #1: schema_validator_unit_test .......   Passed    0.15 sec

100% tests passed out of 1

Label Time Summary:
schema_validator    =   0.15 sec*proc (1 test)

Total Test time (real) =   0.15 sec
```

Verbatim test-tool and unit-test summary output:

```text
[Test schema_validator] validated against 'wazuh-states-inventory-hardware': OK
OK
[==========] 91 tests from 2 test suites ran. (135 ms total)
[  PASSED  ] 91 tests.
```

JSON command over all 17 files:

```sh
python3 -c 'import json; from pathlib import Path; files = sorted(Path("src/external/indexer-plugins").glob("*.json")); assert len(files) == 17; [json.load(open(f)) for f in files]; print("PASS: all 17 templates parse as JSON")'
```

```text
PASS: all 17 templates parse as JSON
```

`python3 /tmp/37532-container-validation/check.py` re-read and compared pristine/edited templates, checked that changes are limited to container mappings/default search, and applied the patch in a synthetic upstream-path tree using `git apply --check -p1` followed by `git apply -p1`, comparing all resulting bytes. Patch generated using git diff --no-index for each pristine/edited pair, rewriting diff/---/+++ paths to a/plugins/setup/src/main/resources/templates/states/... and b/....

For representative validation, compiled the real baseline_rows.cpp with a temporary C++ caller invoking BuildContainerContextJson. Inputs use captured context values from available report §22.9 (writer, pod IP 10.244.0.5, pod/node names, serviceaccount mount, annotation), with representative full IDs/digest, restart count, labels, and an additional manifest-valued annotation. This is generated real serializer output, not a claim of an unmodified live capture. Added a valid file subtree and invoked the rebuilt library's C API against wazuh-states-fim-files. Document and caller are in /tmp/37532-container-validation/{document.json,context.cpp}; helper/check/build logs remain there for this workspace session.

```text
PASS: re-read all 12 edited templates; dynamic: strict unchanged; other 5 byte-identical
PASS: synthetic pristine tree git apply --check -p1 and apply reproduce all 12 files
PASS: real BuildContainerContextJson Kubernetes output plus file fields validates against embedded patched fim-files
PASS: malformed IP rejected: container.network[0].ip: Invalid IP address format: invalid
PASS: unknown array-element field rejected: container.network[0].unexpected: Field not allowed in strict mode
```

`git diff --check` emitted no output (success). No commits made. Existing untracked .serena/ left untouched. Deliverables are this document, 37532-indexer-plugins-container.patch (only the twelve upstream templates), twelve ignored local templates, and the validator source/test edits.
