# Migrating CDB lists to KVDB

In Wazuh 4.x, rules looked up threat data in CDB (Constant Database) lists stored in `/var/ossec/etc/lists/`. In Wazuh 5.0 the Engine has no rules; it looks values up in KVDBs (Key-Value Databases) from its decoders. CDB lists are not carried over automatically — you must convert each list to a KVDB and rewrite the rules that used it as decoder `check` and `normalize` stages.

## 0. Migration prerequisites

Read the [Engine introduction for related migrations](engine-introduction.md) first: it explains the decoder stages (`check`, `normalize`) and the content spaces this guide relies on.

## 1. Structural differences between CDB and KVDB

- In 4.x, CDB lookups appeared only in rules (the `<list>` element). In 5.x, KVDB lookups are helper functions in decoder (and filter) stages. Rule-level CDB lookup logic must be moved into the decoder that processes those events.
- CDB lists were plain `key:value` text files in `/var/ossec/etc/lists/`, compiled by the manager. A KVDB is a document with an `id`, a name (`metadata.title`, the name helpers use), an `enabled` flag and a `content` object; it belongs to an integration, is stored in wazuh-indexer, and is synced to the Engine automatically.
- A CDB value was a string. A KVDB value is any JSON value: string, number, boolean, object or array.
- A decoder can only use a KVDB that is listed, and enabled, in the `kvdbs` of its own integration; otherwise the decoder fails to build (`KVDB '<name>' is not declared in the integration`).

## 2. Implementation equivalences

| CDB `lookup` type | 5.x KVDB helper | Decoder stage |
|-------------------|-----------------|---------------|
| `match_key` | `kvdb_match('db_name')` | `check` |
| `not_match_key` | `kvdb_not_match('db_name')` | `check` |
| `match_key_value` | `kvdb_get('db_name', $field)` into a temporary field, then a check on that field | `normalize` (`map`, then `check` + `map`) |
| `address_match_key` (exact IPs) | `kvdb_match('db_name')` | `check` |
| `address_match_key` (network prefixes) | No KVDB equivalent — use `ip_cidr_match` instead (IPv4 only) | `check` |
| `not_address_match_key` (exact IPs) | `kvdb_not_match('db_name')` | `check` |
| `not_address_match_key` (network prefixes) | No KVDB equivalent — negate `ip_cidr_match` in a conditional expression: `NOT ip_cidr_match($source.ip, '10.0.0.0', '8')` | `check` |
| `address_match_key_value` (exact IPs) | As `match_key_value` | `normalize` |

The full signatures are in the [helper functions reference](../../ref/modules/engine/ref-helper-functions.md#kvdb_match).

## 3. How to migrate CDB files to KVDB files

### 3.1. Step-by-step guide to migrate a CDB file to KVDB file

1. Make a backup of your CDB lists.

```bash
# On the 4.x manager
sudo mkdir -p /tmp/cdb-migration
sudo cp -r /var/ossec/etc/lists /tmp/cdb-migration
sudo cp -r /var/ossec/etc/rules/ /tmp/cdb-migration
```

2. **Structure**: Write the skeleton of the KVDB. `metadata.title` is the KVDB name that helpers such as `kvdb_match('ips_list')` refer to; `id`, `metadata.title`, `enabled` and `content` are required, and `content` must be an object:

```yaml
id: <replace-with-a-new-uuidv4>
metadata:
  title: ips_list
  description: kvdb listing of ips
  author: <ORGANIZATION/AUTHOR>
  date: <YYYY-MM-DD>
enabled: true
content: {}  # replace with your entries (step 3)
```

3. **Content**: Translate each CDB entry into a `content` entry. In CDB the separator was `:` with no spaces; in YAML the key and value are separated by `: `. Quote the keys: an unquoted key such as `0x1` or `10` is read by YAML as a number, not as the string the Engine compares against. An empty CDB value (`alice:`) becomes an empty string.

```text
0x1:laptop
0x2:printer
0x3:1234
alice:
```

```yaml
content:
  "0x1": laptop
  "0x2": printer
  "0x3": 1234
  "alice": ""
```

### 3.2. Bundle the KVDB in an integration

KVDBs are not registered directly — they are part of an **integration**, the unit of content the Engine pulls from wazuh-indexer. List the KVDB's `id` in the `kvdbs` of the integration, and the decoders that use it in the same integration's `decoders` (see [Integrations](../../ref/modules/engine/README.md#integrations)).

Create the integration, the KVDB and the decoders in the draft space through the Indexer's Content Manager API, promote them to the test space to check them with logtest, then to the custom space (the procedure is in [Migrating rules from 4.x to 5.x](rules-4x-to-5x.md#step-11-deploy-and-test)). The Engine's content synchronization (CMSync) picks up the custom space on its next cycle and rebuilds the policy with the KVDB available to the integration's decoders — see [Content management](../../ref/modules/engine/README.md#content-management-managing-the-engines-processing).

### 3.3. Update your decoders

In 4.x, rules referenced CDB lists via `<list field="..." lookup="...">`. In 5.x, that logic moves
into a decoder using KVDB helper functions in its `check` and `normalize` stages. The examples below
show the most common patterns. In them, `decoder/<parent-decoder>/0` stands for the decoder of your
integration that already normalized the event (the 4.x `<if_group>json</if_group>`), so fields such as
`source.ip` are set when the child runs; labels go to the WCS `tags` field. Every field a decoder writes
must be a WCS field or a temporary field whose name starts with `_`; any other name makes the decoder
fail to build.

#### Example: single-list IP check

**4.x rule:**

```xml
<rule id="110700" level="10">
  <if_group>json</if_group>
  <list field="srcip" lookup="address_match_key">etc/lists/List-one</list>
  <description>IP blacklisted in LIST ONE</description>
  <group>list1,</group>
</rule>
```

**5.x decoder equivalent:**

```yaml
name: decoder/ip-blacklist-list-one/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/<parent-decoder>/0
metadata:
  title: IP blacklisted in LIST ONE
  description: Matches source IPs found in the list_one KVDB.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.ip: kvdb_match('list_one')
normalize:
  - map:
      - tags: array_append(list1)
```

> [!NOTE]
> `kvdb_match` works for exact IP keys. A 4.x `address_match_key` list could also hold network prefixes: keys ending in a dot (`10.`, `192.168.`, `192.168.1.`), matched against the leading octets of the address. There is no KVDB equivalent — replace each prefix with an `ip_cidr_match` check (`192.168.` is `192.168.0.0/16`):
>
> ```yaml
> check:
>   - source.ip: ip_cidr_match('192.168.0.0', '16')
> ```
>
> The second argument is a prefix length or a dotted mask (`'255.255.0.0'`); the helper handles IPv4 only.
> If a single CDB list mixed exact IPs and prefixes, split them: the exact IPs into a KVDB, the prefixes into `ip_cidr_match` checks. All conditions of a `check` list must hold, so an "exact IP **or** prefix" test needs a conditional expression, for example `check: kvdb_match($source.ip, 'list_one') OR ip_cidr_match($source.ip, '192.168.0.0', '16')`.

#### Example: allowlist check (not_match_key)

`not_match_key` alerted when a field value was **absent** from a CDB list — typically used to flag events from users or IPs not present in an allowlist. In 5.x, use `kvdb_not_match` in the decoder's `check` stage.

**4.x rule:**

```xml
<rule id="110750" level="10">
  <if_group>json</if_group>
  <list field="srcuser" lookup="not_match_key">etc/lists/authorized_users</list>
  <description>Login attempt from unauthorized user</description>
  <group>auth,</group>
</rule>
```

With a CDB allowlist such as:

```
alice:
bob:
carol:
```

**5.x decoder equivalent:**

```yaml
name: decoder/unauthorized-user-login/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/<parent-decoder>/0
metadata:
  title: Login attempt from unauthorized user
  description: Flags login events from users not found in the authorized_users KVDB.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - user.name: kvdb_not_match('authorized_users')
normalize:
  - map:
      - tags: array_append(auth)
```

The decoder only accepts the event when `user.name` is **not** a key in the `authorized_users` KVDB; for authorized users the `check` fails and the Engine tries the next sibling decoder. `kvdb_not_match` also fails when the field is absent or is not a string, so events without a user name are not flagged.

#### Example: key lookup with value check

`match_key_value` checked that a key existed in the CDB **and** its stored value matched the `check_value` pattern. In 5.x, use `kvdb_get` in a `normalize` block to retrieve the value into a temporary field, then test it in the `check` of a following `normalize` block.

**4.x rule:**

```xml
<rule id="110800" level="10">
  <if_group>json</if_group>
  <list field="srcip" lookup="match_key_value" check_value="malware">etc/lists/threat_types</list>
  <description>Source IP is a known malware host</description>
</rule>
```

With CDB entries such as:

```
1.2.3.4:malware
5.6.7.8:botnet
```

**5.x decoder equivalent:**

```yaml
name: decoder/ip-threat-type/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/<parent-decoder>/0
metadata:
  title: Source IP threat-type lookup
  description: Enriches events with the threat type stored for the source IP in threat_types KVDB.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
normalize:
  - map:
      - _threat_type: kvdb_get('threat_types', $source.ip)
  - check:
      - _threat_type: malware
    map:
      - tags: array_append(malware)
```

The first `normalize` block maps the KVDB value into `_threat_type`, a temporary field (removed before the event is indexed, unless the policy sets `cleanup_decoder_variables` to `false`); the second block only applies its `map` when that value equals `malware`. A `normalize` block whose `check` fails is skipped without rejecting the event, and `kvdb_get` leaves the field unset when the key is absent, so the decoder accepts every event its parent passes and only tags the matching ones. The check is an exact comparison; a 4.x `check_value` pattern that matched more than one value needs a helper such as `regex_match` or `contains` instead.

#### Example: AND across two lists

A rule that chains on a parent rule (via `<if_sid>`) to require a match in both lists becomes a child decoder whose parent is the first decoder:

**4.x rules:**

```xml
<rule id="110700" level="10">
  <if_group>json</if_group>
  <list field="srcip" lookup="address_match_key">etc/lists/List-one</list>
  <description>IP blacklisted in LIST ONE</description>
</rule>

<rule id="110710" level="10">
  <if_sid>110700</if_sid>
  <list field="srcip" lookup="address_match_key">etc/lists/List-two</list>
  <description>IP blacklisted in LIST ONE and LIST TWO</description>
</rule>
```

**5.x decoder equivalent:**

```yaml
name: decoder/ip-blacklist-both-lists/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/ip-blacklist-list-one/0
metadata:
  title: IP blacklisted in LIST ONE and LIST TWO
  description: Matches source IPs found in both list_one and list_two KVDBs.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.ip: kvdb_match('list_two')
normalize:
  - map:
      - tags: array_append(list2)
```

The child decoder only runs if its parent (`decoder/ip-blacklist-list-one/0`) already matched, so the AND condition is preserved through the parent–child relationship.

#### Example: OR across two lists

Two independent 4.x rules that each check a different list — with no `<if_sid>` relationship between them — produce alerts whenever the condition of *either* rule is met.

**4.x rules:**

```xml
<rule id="110700" level="10">
  <if_group>json</if_group>
  <list field="srcip" lookup="address_match_key">etc/lists/List-one</list>
  <description>IP blacklisted in LIST ONE</description>
</rule>

<rule id="110720" level="10">
  <if_group>json</if_group>
  <list field="srcip" lookup="address_match_key">etc/lists/List-two</list>
  <description>IP blacklisted in LIST TWO</description>
</rule>
```

**5.x decoder equivalent:**

Two sibling decoders under the same parent implement OR logic. The Engine evaluates siblings in order (integration order in the policy, then decoder order in the integration — see [Decoder tree traversal order](../../ref/modules/engine/README.md#decoder-tree-traversal-order)) and follows the first one that accepts the event, so an event in either list is accepted by one of them.

```yaml
name: decoder/ip-blacklist-list-one/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/<parent-decoder>/0
metadata:
  title: IP blacklisted in LIST ONE
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.ip: kvdb_match('list_one')
normalize:
  - map:
      - tags: array_append(list1)
```

```yaml
name: decoder/ip-blacklist-list-two/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/<parent-decoder>/0
metadata:
  title: IP blacklisted in LIST TWO
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.ip: kvdb_match('list_two')
normalize:
  - map:
      - tags: array_append(list2)
```

> [!NOTE]
> Because the Engine follows the first matching sibling, when an IP appears in both lists only the first decoder fires for that event. If you need both labels applied for overlapping entries, use the AND pattern — make the second decoder a child of the first — and merge the labels in its `normalize` block.

## Limitations

| Area | 4.x CDB behavior | 5.x KVDB behavior |
|------|------------------|-------------------|
| **Network prefix matching** | `address_match_key` / `not_address_match_key` with prefix keys ending in a dot (e.g., `192.168.:`) | No KVDB equivalent. Replace each prefix with an explicit `ip_cidr_match` check in the decoder's `check` stage (IPv4 only). |
| **Mixed exact-IP and prefix lists** | Single CDB file can hold both `1.2.3.4:` and `10.:` entries | Must be split: exact IPs into a KVDB, prefixes into explicit `ip_cidr_match` entries. |
| **OR with overlapping entries** | Two independent rules each fire when their condition is met | Sibling decoders implement OR, but only the first match fires per event. Use the AND (parent–child) pattern when an entry can appear in multiple lists and both labels are needed. |
| **Rule-level logic** | `<list>` could appear alongside `<match>`, `<regex>`, or `<field>` in a rule | All conditions move into a single decoder's `check` block. Combine KVDB helpers with other check conditions in the same `check` list, or in one conditional expression when you need `OR`/`NOT`. |
| **KVDB scope** | A CDB list declared in the manager configuration could be used by any rule | A KVDB can only be used by decoders of the integration that lists it in its `kvdbs`. |

## Related resources

- [Key Value Databases (KVDBs)](../../ref/modules/engine/README.md#key-value-databases-kvdbs)
- [Engine content management](../../ref/modules/engine/README.md#content-management-managing-the-engines-processing)
- [KVDB helper functions reference](../../ref/modules/engine/ref-helper-functions.md)
- [Decoders reference](../../ref/modules/engine/README.md#decoders)
- [Engine integrations](../../ref/modules/engine/README.md#integrations)
