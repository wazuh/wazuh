# Source

1. [Directory structure](#directory-structure)
2. [Component structure](#component-structure)

# Directory structure

```plaintext
source/
│
├── api/
├── base/
├── bk/
├── builder/
├── cmds/
├── conf/
├── defs/
├── geo/
├── hlp/
├── kvdb/
├── logiexpr/
├── metrics/
├── mmdb/
├── parsec/
├── proto/
├── queue/
├── rbac/
├── router/
├── schemf/
├── server/
├── sockiface/
├── store/
├── wdb/
├── yml/
```

# Component structure

Each component of the engine is organized in a structured way to facilitate its development, maintenance and testing. The directory structure is designed to clearly separate interfaces, source code, headers, and tests.

```plaintext
<component>/
├── interface/
│   └── <component_interface.h>
│
├── source/
│   ├── <component>.cpp
│   └── <component>_impl.cpp
│
├── include/
│   └── <component>/
│       └── <component>.h
│
└── test/
    ├── mocks/
    │   └── <component>_mocks.h 
    │
    └── src/
        ├── component/
        │   └── <component>_test.cpp
        │
        └── unitario/
            └── <component>_unit_test.cpp
```

## Interface
Contains the public interfaces of the component. Interfaces define how other components can interact with the current component.

## Source
The entire source code of the component is located. This includes the implementation of the component and any supporting code necessary for its operation.

## Include
Contains the header files for the component. Header files define the public interfaces and data structures that the component provides.

## Test

Contains mocks that simulate the behavior of dependent objects or components to test the component in isolation, and both component and unit testing