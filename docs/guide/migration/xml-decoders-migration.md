# Migrating Custom Decoders from XML format to YAML

## 0. Migration prerequisites

In order to have a better experience on migrating your custom decoders, please take a look on [this engine introduction](engine-introduction.md)

## 1. Specific decoders features supported in YAML

### 1.1. Supported YAML tags table

Check [engine documentation](../../ref/modules/engine/README.md#assets) to dive into what fields are supported in a YAML decoder.

### 1.2. Metadata table

Check [engine documentation](../../ref/modules/engine/README.md#assets) to dive into what fields are supported in `metadata` field.

### 1.3. Normalize array

Check [engine documentation](../../ref/modules/engine/README.md#decoders) to dive into what fields are supported in `normalize` field.

#### Valid blocks combination

| Combination | Case of use |
|-------------|-------------|
| map | Unconditional assignments |
| check + map | Assign only if condition holds |
| check + parse\| + map | Gated extraction, then assignment |
| check + parse\| | Gated extraction, no assignment |
| parse\| | Extraction only |

## 2. XML to YAML equivalences

| XML element | YAML equivalent |
|-------------|-----------------|
| \<decoder name="..."\> ... \</decoder\> | name: ... |
| \<parent\>...\</parent\> | parents: ... |
| \<prematch\>...\</prematch\> | check: ... + parse\|\<field\>: ... |
| \<regex\>...\</regex\> / \<order\> ... \</order\> | parse\|\<field\>: ... |
| \<program_name\>...\</program_name\> | check: $process.name == '...' |

## 3. Unsupported patterns

| XML element | Reason |
|-------------|-----------------|
| \<plugin_decoder\> | Plugin decoders were hooks into hardcoded C handlers (JSON_Decoder, SyscollectorDeltas, etc.). 5.x replaced that extensibility model with native YAML-driven parsing, so the plugin hook has nothing to call. |
| \<json_null_field\> | Controlled how the 4.x JSON plugin handled null values. 5.x handles JSON natively with different semantics, there's no plugin to configure. |
| \<type\> | 4.x used decoder types (syslog, json, windows, etc.) to route logs to built-in handlers. 5.x replaced the entire routing layer, as decoders are pure YAML pipelines with explicit parse expressions; there's nothing to route. |
| \<fts\> | First-Time-Seen was a stateful feature built into the decoder layer. 5.x decoders are stateless by design; each event is processed independently. |
| \<ftscomment\> | A human-readable label attached to the `<fts>` feature, used to describe what triggered the first-time-seen alert. Since FTS is removed in 5.x, this annotation has no equivalent. |
| \<accumulate/\> | Allowed a decoder to accumulate data across multiple log lines. Also stateful, same reason as \<fts\>, the 5.x decoder layer has no cross-event state. |
| \<use_own_name\> | In 4.x, sibling decoders could share the same name; \<use_own_name\> made a child report its own name instead of the parent's. 5.x enforces unique names (decoder/\<name\>/\<version\>), so the disambiguation is unnecessary. |
| \<prematch type="pcre2"\> / \<regex type="pcre2"\> | 4.x defaulted to POSIX ERE and let you opt into PCRE2. 5.x logpar is not regex-based at all — it's a structured field extraction language — so the regex engine choice is irrelevant. |
| \<prematch offset="after_parent"\> / \<regex offset="after_prematch"\> | Offset (after_parent, after_prematch, after_regex) was a performance hint telling the regex engine where to start scanning. Logpar expressions are sequential parsers that naturally track position; no offset hint is needed. |

## 4. How to migrate a custom decoder in XML format to YAML

Follow these steps in order to migrate a decoder:

1. **Header**: set name as decoder/\<your-name\>/0 (version is 0 for all user-created decoders in 5.0 — versioning is reserved for future use), generate a UUIDv4 for id, set enabled: true, and fill metadata.
2. **\<parent\>**: Transform this section in **parents** listing the parent decoder(s). A child decoder only runs after one of its listed parent decoders has already matched the event.
3. **\<prematch\>**: Transform this section in **check**. Rewrite it as a boolean expression over already-decoded fields (e.g. `$process.name == 'sshd'`). This only filters; it never extracts.

> [!NOTE]
> In 4.x, `<prematch>` was a pure pre-filter and its capture groups were never mapped to `<order>` fields. Only `<regex>` capture groups mapped to `<order>`. No extraction is lost when migrating `<prematch>` to `check`.

4. **\<regex\> + \<order\>**: Transform these in **parse|\<field\>**, where `<field>` is the source field to parse (typically `message` for syslog events). Convert each regex into a logpar expression. Replace each capture group with a named, schema-typed field placeholder:
   - **Schema fields auto-type**: `<source.ip>` (IP), `<source.port>` (number), `<@timestamp>` (date).
   - **Force a type with a suffix**: `<source.port/long>`.
   - **Optional segments**: `connected from <source.ip>(? port <source.port>)` — matches an optional ` port N` suffix. For optional fields: `<?optional.field>`.
   - **Match-but-don't-map (wildcard)**: `<~>` matches and discards any content. Add an optional name to distinguish multiple wildcards in one expression (`<~skip>`), and a type suffix to constrain what it matches (`<~skip/long>` only matches integer content).
   - **Temporary vars** use a _ prefix (e.g. `<_ssh.event>`) and are stripped after decoding.
   - **You can list multiple expressions under one parse|**: they're tried in order, first match wins.
5. **Add static assignments**: Anything you set unconditionally (event category, dataset, outcome) goes in **map** blocks inside normalize. Each normalize block can have its own check, parse|, and map, and failed blocks are skipped rather than failing the whole decoder.

## 5. Reference YAML examples

```yaml
name: decoder/ssh-auth-failure/0
id: <replace-with-a-new-uuidv4> 
enabled: true
parents:
  - decoder/syslog/0
metadata:
  title: SSH/Sudo authentication failure
  description: Extracts failed authentication attempts from sshd and sudo processes.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
  references:
    - https://github.com/wazuh/wazuh/tree/main/docs/ref/modules/engine/
  compatibility:
    - Wazuh 5.0
  supports:
    - Ubuntu 24.04 LTS
check: $process.name == 'sshd' OR $process.name == 'sudo'
normalize:
  - parse|message:
      - "<~>: Failed password for <user.name> from <source.ip>"
    map:
      - event.action: authentication-failure
      - event.outcome: failure
      - event.category: array_append(authentication)
```

```yaml
name: decoder/sshd-base/0
id: <replace-with-a-new-uuidv4> 
enabled: true
metadata:
  title: Base sshd process event
  description: Base decoder for sshd events. Sets event.kind before child decoders extract details.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - process.name: sshd
normalize:
  - map:
      - event.kind: event
```

## 6. Conversion examples

### 6.1. Legacy XML:

```xml
<decoder name="auth_decoder">
  <parent>syslog</parent>
  <prematch>^(sshd|sudo)</prematch>
  <regex>(\w+): Failed password for (\w+) from ([\d.]+)</regex>
  <order>process.name,user.name,source.ip</order>
</decoder>
```

### 6.2. Migrated YAML:

```yaml
name: decoder/auth-failure/0
id: <replace-with-a-new-uuidv4> 
enabled: true
parents:
  - decoder/syslog/0
metadata:
  title: SSH/Sudo authentication failure
  description: Extracts failed authentication attempts
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check: $process.name == 'sshd' OR $process.name == 'sudo'
normalize:
  - parse|message:
      - "<process.name>: Failed password for <user.name> from <source.ip>"
    map:
      - event.action: authentication-failure
      - event.outcome: failure
      - event.category: array_append(authentication)
```
