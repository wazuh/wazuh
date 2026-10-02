# Introduction to Engine module

## Main changes between 4.x and 5.x

5.x changes how decoders and the other assets work, both in their format and in how events flow through them. In 5.x, event processing is done by the Engine (`wazuh-manager-analysisd`).

In 4.x, decoders were written in XML; in 5.x they are YAML. YAML represents structured and typed values (strings, numbers, booleans, arrays and objects) in a clearer and more maintainable form. 5.x also drops the 4.x pre-decoding stage, which could fail to parse the input correctly and produce inaccurate values.

In 4.x, decoders formed a shallow tree: a decoder could have children, but those children could not have children of their own, so the tree had a maximum depth of 2. When an event arrived, the decoders were tried one by one until one succeeded. When a decoder had children, they were tried in order until one of them also succeeded; if all of them failed, the parent failed too and the event passed to the next decoder.

In 5.x, a decoder declares its position in the tree with a `parents` list, which can name **one or more** parent decoders, so the tree can be any depth. The flow is more vertical than horizontal, but it is in general the same process.

Some 4.x decoder options, such as `<use_own_name>`, have no 5.x counterpart: every asset has a unique name, so the option has nothing left to do. For the 5.x asset format and the decoder tree, see the [Engine reference](../../ref/modules/engine/README.md); for converting decoders, see [Migrating decoders from XML to YAML](xml-decoders-migration.md).
