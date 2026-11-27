# Introduction to Engine module

## Main changes between 4.x and 5.x

5.x changes how decoders and the other assets work, both in their format and in how events flow through them. In 5.x, event processing is done by the Engine (`wazuh-manager-analysisd`), and the manager no longer evaluates rules: detection runs in the Wazuh Indexer (see [Migrating rules from 4.x to 5.x](rules-4x-to-5x.md)).

In 4.x, decoders were written in XML; in 5.x they are YAML, which represents structured and typed values (strings, numbers, booleans, arrays and objects). 5.x also has no pre-decoding stage: the Engine receives the raw log in `event.original`, and the syslog header that 4.x pre-decoded (timestamp, hostname, program name) is parsed by decoders like any other part of the log (see [Event format](../../ref/modules/engine/README.md#event-format)).

In 4.x, decoders formed a shallow tree: a decoder could have children, but those children could not have children of their own, so the tree had a maximum depth of 2. The decoders without a parent were tried in order until one matched; then its children were tried in order, and the first one that matched decoded the event. When none of the children matched, decoding stopped there: the event kept the parent's name and no other decoder was tried.

In 5.x, a decoder declares its position in the tree with a `parents` list, which can name **one or more** parent decoders, so the tree can be any depth. A decoder without `parents` hangs from its integration's `default_parent` or, when the integration has none, from the policy's root decoder. Every event starts at the root decoder; when a decoder accepts it, its children are tried in order and only the first one that accepts it is followed. As in 4.x, when none of the children accepts the event, it keeps what the parent decoded and no sibling of the parent is tried. See [Decoder tree traversal order](../../ref/modules/engine/README.md#decoder-tree-traversal-order).

A 5.x decoder runs its stages in a fixed order: `check` (conditions on the event), `parse|<field>` (parser expressions that extract fields from one field) and `normalize` (blocks of `check`, `parse|<field>` and `map` that assign values). The decoder accepts the event when its `check` and `parse|<field>` succeed; a `normalize` block that fails is skipped without rejecting the event. See [Stages](../../ref/modules/engine/README.md#stages).

Decoders, KVDBs and filters are not files on the manager. They are assets of an **integration**, stored in the Wazuh Indexer and created through its Content Manager in a user **space**: Draft, then Test (where logtest runs them), then Custom. The Engine synchronizes the Standard space (the content Wazuh ships) and the Custom space from the Indexer and runs both. See [Content management](../../ref/modules/engine/README.md#content-management-managing-the-engines-processing) and [Integrations](../../ref/modules/engine/README.md#integrations).

Some 4.x decoder options, such as `<use_own_name>`, have no 5.x counterpart: every asset has a unique name, so the option has nothing left to do. For the 5.x asset format, see the [Engine reference](../../ref/modules/engine/README.md#assets); for converting decoders, see [Migrating decoders from XML to YAML](xml-decoders-migration.md), and for CDB lists, [Migrating CDB lists to KVDB](cdb-to-kvdb-migration.md).
