# Introduction to Engine module

## Main changes between 4.x and 5.x

5.x has changed greatly in comparison to its predecessor, 4.x. Some of the main changes that affect how decoders and other assets work is the internal architecture and workflow around some items.

Decoders in 4.x were written in XML, whereas decoders in 5.x are defined in YAML. This decision was mainly driven by YAML's ability to represent structured and typed values, such as strings, numbers, booleans, arrays, and objects, in a clearer and more maintainable format. This change also eliminates the pre-decoding stage used by the 4.x decoders, which could sometimes fail to parse the input correctly and produce inaccurate values.

In terms of the tree structure of the decoders "chain"; in 4.x the structure decoders followed was like this: `decoder-1` -> `decoder-2` -> `...` -> `decoder-n`. Each of these decoders could have one or more children and these children **could not** have more children, thus making a tree of `max-depth of 2`. Regarding the workflow, whenever an event arrived, the decoders would try to decode it one by one until one of them succeeded. Whenever a decoder had children, they would be tested sequentially until one of them also succeded, and if all of them failed then the parent decoder would also fail, passing the event to the next decoder.

This architecture has disappeared in 5.x, as one decoder can have **one or more** parents, thus making the tree be a `max-depth of n nodes` tree. The flow is a bit different in this version, as it is more vertical than horizontal but it is in general the same process.

This change would make some decoder fields like `<use_own_name>` disappear, as unique names are enforced, so it became useless. For more information, check the following [link](../../ref/modules/engine/README.md)
