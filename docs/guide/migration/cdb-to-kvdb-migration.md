# Migrating CDB lists to KVDB

In Wazuh 4.x,  rules looked up threat data using CDB (Constant Database) lists stored in `/var/ossec/etc/lists/`. In Wazuh 5.0, the Engine replaces these rules and uses KVDB (Key-Value Database) for the same purpose. CDB lists are not carried over automatically — you must convert each list to a KVDB and rewrite the rules that used it as decoder `check` and `map` stages.

## 0. Migration prerequisites

In order to have a better experience on migrating your custom decoders, please take a look on [this engine introduction](engine-introduction.md)

## 1. Structural differences between CDB and KVDB

- In 4.x, CDB lookups appeared in rules (`<list>` tag) and decoders. In 5.x, all KVDB lookups live in decoders. Rule-level CDB lookup logic must be moved into the decoder that processes those events.
- CDB lists had no defined schema. KVDBs are YAML documents with explicit `content` entries.
- CDB lists were files in `/var/ossec/etc/lists/`. KVDBs are defined in YAML, bundled inside an integration, stored in wazuh-indexer, and synced to the Engine automatically.
- Both use a `key: value` structure. KVDBs additionally support nested fields and arrays as values.

## 2. Implementation equivalences

| CDB `lookup` type | 5.x KVDB helper | Decoder stage |
|-------------------|-----------------|---------------|
| `match_key` | `kvdb_match('db_name')` | `check` |
| `not_match_key` | `kvdb_not_match('db_name')` | `check` |
| `match_key_value` | `kvdb_get('db_name', $field)` + filter on the retrieved value | `normalize` (`map` + `check`) |
| `address_match_key` (exact IPs) | `kvdb_match('db_name')` | `check` |
| `address_match_key` (subnets) | No direct equivalent — use `ip_cidr_match` instead | `check` |
| `not_address_match_key` (exact IPs) | `kvdb_not_match('db_name')` | `check` |
| `not_address_match_key` (subnets) | No direct equivalent | `check` |

## 3. How to migrate CDB files to KVDB files

### 3.1. Step-by-step guide to migrate a CDB file to KVDB file

1. Make a backup of your CDB lists.

```bash
sudo mkdir -p /tmp/cdb-migration
cp -r /var/ossec/etc/lists /tmp/cdb-migration
cp -r /var/ossec/etc/rules/ /tmp/cdb-migration
```

2. **Structure**: Write the skeletal structure of your kvdb:

```yaml
kvdbs:
  - id:  <replace-with-a-new-uuidv4> 
    metadata: 
      title: ips_list
      description: kvdb listing of ips
      author: <ORGANIZATION/AUTHOR OF DECODER>
      date: <YYYY-MM-DD>
    enabled: true
    content:
      # Here will go all your cdb key:value
```

3. **Content**: Translate each CDB entry into YAML. In CDB the separator was `:` with no spaces; in KVDB the key and value are separated by `: ` (standard YAML mapping).

```
0x1:laptop
0x2:printer
0x3:1234
```

```yaml
content:
  0x1: laptop
  0x2: printer
  0x3: 1234
```

### 3.2. Bundle the KVDB in an integration

KVDBs are not registered directly — they are part of an **integration**, which is the unit of content that the Engine pulls from wazuh-indexer. Create an integration YAML that references the KVDB UUID and the decoder UUIDs that will use it.

Upload the integration and KVDB to the Custom space in wazuh-indexer. The Engine's content manager (CMSync) picks up the change on its next synchronization cycle and makes the KVDB available to decoders. For the upload procedure, see the [Engine content management reference](../../ref/modules/engine/README.md#content-management-managing-the-engines-processing).

### 3.3. Update your decoders

In 4.x, rules referenced CDB lists via `<list field="..." lookup="...">`. In 5.x, that logic moves
into a decoder using KVDB helper functions in its `check` and `normalize` stages. The examples below
show the most common patterns.

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
  - decoder/json/0
metadata:
  title: IP blacklisted in LIST ONE
  description: Matches source IPs found in the list_one KVDB.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.ip: kvdb_match('list_one')
normalize:
  - map:
      - wazuh.threat.groups: array_append(list1)
```

> [!NOTE]
> `kvdb_match` works for exact IP keys. If your CDB list contained subnet entries (e.g. `192.168.0.0/16:`), there is no KVDB equivalent — replace those entries with explicit `ip_cidr_match` checks in the decoder's `check` stage:
> ```yaml
> check: 
>   - ip_cidr_match/192.168.0.0/16/$source.ip
> ```
> If a single CDB list mixed exact IPs and CIDR blocks, split them into a KVDB (for exact IPs) and explicit `ip_cidr_match` entries (for subnets) in the same `check` block.

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
  - decoder/json/0
metadata:
  title: Login attempt from unauthorized user
  description: Flags login events from users not found in the authorized_users KVDB.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.user.name: kvdb_not_match('authorized_users')
normalize:
  - map:
      - wazuh.threat.groups: array_append(auth)
```

The decoder only proceeds when `source.user.name` is **not** a key in the `authorized_ed users are silently dropped at the `check` stage.

#### Example: key lookup with value check

`match_key_value` checked that a key existed in the CDB **and** its stored value matched a pattern. In 5.x, use `kvdb_get` in a `map` block to retrieve the value, then filter on it in a following `check` block.

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
  - decoder/json/0
metadata:
  title: Source IP threat-type lookup
  description: Enriches events with the threat type stored for the source IP in threat_types KVDB.
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
normalize:
  - map:
      - source.threat_type: kvdb_get('threat_types', $source.ip)
```

The first `normalize` block maps the KVDB value into `source.threat_type`; the second block filters to only proceed when the value equals `malware`. A failed `normalize` block is skipped without rejecting the event, so if the key is absent the decoder continues normally.

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
      - wazuh.threat.groups: array_append(list2)
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

Two sibling decoders under the same parent implement OR logic. The Engine evaluates siblings in order and follows the first one that matches, so each decoder fires independently on events that satisfy its own `check`.

```yaml
name: decoder/ip-blacklist-list-one/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/json/0
metadata:
  title: IP blacklisted in LIST ONE
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.ip: kvdb_match('list_one')
normalize:
  - map:
      - wazuh.threat.groups: array_append(list1)
```

```yaml
name: decoder/ip-blacklist-list-two/0
id: <replace-with-a-new-uuidv4>
enabled: true
parents:
  - decoder/json/0
metadata:
  title: IP blacklisted in LIST TWO
  author: <ORGANIZATION/AUTHOR OF DECODER>
  date: <YYYY-MM-DD>
check:
  - source.ip: kvdb_match('list_two')
normalize:
  - map:
      - wazuh.threat.groups: array_append(list2)
```

> [!NOTE]
> Because the Engine follows the first matching sibling, when an IP appears in both lists only the first decoder fires for that event. If you need both labels applied for overlapping entries, use the AND pattern — make the second decoder a child of the first — and merge the labels in its `normalize` block.

## Limitations

| Area | 4.x CDB behavior | 5.x KVDB behavior |
|------|------------------|-------------------|
| **Subnet matching** | `address_match_key` / `not_address_match_key` with CIDR notation (e.g., `192.168.0.0/16:`) | No KVDB equivalent. Replace each subnet with an explicit `ip_cidr_match` check in the decoder's `check` stage. |
| **Mixed exact-IP and subnet lists** | Single CDB file can hold both `1.2.3.4:` and `10.0.0.0/8:` entries | Must be split: exact IPs into a KVDB, subnets into explicit `ip_cidr_match` entries. |
| **OR with overlapping entries** | Two independent rules each fire when their condition is met | Sibling decoders implement OR, but only the first match fires per event. Use the AND (parent–child) pattern when an entry can appear in multiple lists and both labels are needed. |
| **Rule-level logic** | `<list>` could appear alongside `<match>`, `<regex>`, or `<field>` in a rule | All conditions move into a single decoder's `check` block. Combine KVDB helpers with other check conditions in the same `check` array. |

## Related resources

- [Key Value Databases (KVDBs)](../../ref/modules/engine/README.md#key-value-databases-kvdbs)
- [Engine content management](../../ref/modules/engine/README.md#content-management-managing-the-engines-processing)
- [KVDB helper functions reference](../../ref/modules/engine/ref-helper-functions.md)
- [Decoders reference](../../ref/modules/engine/README.md#decoders)
- [Engine integrations](../../ref/modules/engine/README.md#integrations)
