# cmcrud

## Overview

The **cmcrud** module is the **CRUD service layer** for the Wazuh engine's Content Manager. It sits between the HTTP API handlers and the underlying `cmstore`, mediating all create / read / update / delete operations on namespaces, policies, and resources (decoders, filters, outputs, integrations, KVDBs).

Before any mutation reaches the store, `cmcrud` receives a structured `json::Json` payload, applies type-specific adaptations (canonical field ordering for assets), and delegates structural validation to `builder::IValidator`. This guarantees that every artifact persisted in `cmstore` has already been checked for consistency.

## Architecture

```
  ┌────────────────┐      ┌────────────────┐
  │  api/cmcrud    │      │    cmsync       │
  │  (HTTP layer)  │      │ (sync service)  │
  └───────┬────────┘      └───────┬─────────┘
          │  ICrudService         │  ICrudService
          ▼                       ▼
  ┌──────────────────────────────────────────┐
  │              CrudService                 │
  │                                          │
  │  • Structured JSON handling              │
  │  • Asset adaptation (canonical ordering) │
  │  • Validation delegation                 │
  │  • Import orchestration with rollback    │
  └──────┬─────────────────────┬─────────────┘
         │ ICMStore            │ IValidator
         ▼                     ▼
  ┌──────────────┐     ┌─────────────────┐
  │   cmstore    │     │ builder module  │
  │ (persistent  │     │ (structural     │
  │  content)    │     │  validation)    │
  └──────────────┘     └─────────────────┘
```

## Key Concepts

### Validation-Before-Mutation

`CrudService` never writes to `cmstore` without validating first. Depending on the resource type it calls:

| Resource Type | Validation Path |
|---|---|
| **Policy** | `IValidator::softPolicyValidate()` |
| **Integration** | `IValidator::softIntegrationValidate()` |
| **Asset** (decoder / filter / output) | `IValidator::validateAsset()` |
| **KVDB** | Parsed via `cm::store::dataType::KVDB::fromJson()` (structural check only) |

A `force` / `softValidation` flag on the import paths can relax or skip some of these checks.

### Asset Adaptation

Before storing an asset, its JSON representation is run through a type-specific *adapter* that enforces canonical field ordering:

- `detail::adaptDecoder()` — canonical ordering for decoders
- `detail::adaptFilter()` — canonical ordering for filters
- `detail::adaptOutput()` — canonical ordering for outputs

This ensures deterministic serialisation regardless of the order in which the user supplied the fields.

### Namespace Import

Import is an all-or-nothing operation. Resources are ingested in a strict order to satisfy dependency chains:

1. **KVDBs**
2. **Decoders**
3. **Filters** (extracted from integrations in the JSON-document overload)
4. **Outputs** (extracted from integrations in the JSON-document overload)
5. **Integrations**
6. **Policy**

If any step fails, a `bestEffortDelete` rollback lambda removes whatever was already created in the namespace.

Two overloads exist:

| Overload | Input | Use Case |
|---|---|---|
| `importNamespace(nsId, jsonDocument, origin, force)` | Single JSON document containing all components | API-driven import (e.g. uploading a full namespace export) |
| `importNamespace(nsId, kvdbs, decoders, integrations, policy, softValidation)` | Pre-parsed component vectors | Programmatic import from `cmsync` |

### Weak-Pointer Resource Model

`CrudService` stores its dependencies (`ICMStore`, `IValidator`) as `std::weak_ptr`. Every public method locks them on entry via `getStore()` / `getValidator()`, throwing `std::runtime_error` if the underlying object has been destroyed. This prevents dangling references and makes lifetime management explicit.

## Directory Structure

```
cmcrud/
├── CMakeLists.txt
├── README.md
├── interface/cmcrud/
│   └── icmcrudservice.hpp          # ICrudService pure-virtual interface + ResourceSummary
├── include/cmcrud/
│   └── cmcrudservice.hpp           # CrudService concrete implementation header
├── src/
│   └── cmcrudservice.cpp           # Full implementation (~750 lines)
└── test/
    ├── mocks/cmcrud/
    │   └── mockcmcrud.hpp          # GMock mock (MockCrudService)
    ├── unit/                       # Unit tests
    └── component/                  # Component tests
```

## Public Interface

### `ICrudService` (namespace `cm::crud`)

```cpp
class ICrudService
{
public:
    virtual ~ICrudService() = default;

    // ── Namespaces ─────────────────────────────────────────
    virtual std::vector<cm::store::NamespaceId> listNamespaces() const = 0;
    virtual void createNamespace(const cm::store::NamespaceId& nsId) = 0;
    virtual bool existsNamespace(const cm::store::NamespaceId& nsId) const = 0;
    virtual void deleteNamespace(const cm::store::NamespaceId& nsId) = 0;

    virtual cm::store::dataType::Policy
    importNamespace(const cm::store::NamespaceId& nsId,
                    std::string_view jsonDocument,
                    std::string_view origin,
                    bool force) = 0;

    virtual void
    importNamespace(const cm::store::NamespaceId& nsId,
                    const std::vector<json::Json>& kvdbs,
                    const std::vector<json::Json>& decoders,
                    const std::vector<json::Json>& integrations,
                    const json::Json& policy,
                    bool softValidation) = 0;

    // ── Policy ─────────────────────────────────────────────
    virtual void upsertPolicy(const cm::store::NamespaceId& nsId,
                              std::string_view document) = 0;
    virtual void deletePolicy(const cm::store::NamespaceId& nsId) = 0;

    // ── Generic Resources ──────────────────────────────────
    virtual std::vector<ResourceSummary>
    listResources(const cm::store::NamespaceId& nsId,
                  cm::store::ResourceType type) const = 0;

    virtual std::string
    getResourceByUUID(const cm::store::NamespaceId& nsId,
                      const std::string& uuid) const = 0;

    virtual void
    upsertResource(const cm::store::NamespaceId& nsId,
                   cm::store::ResourceType type,
                   std::string_view document) = 0;

    virtual void
    deleteResourceByUUID(const cm::store::NamespaceId& nsId,
                         const std::string& uuid) = 0;

    virtual void
    validateResource(cm::store::ResourceType type,
                     const json::Json& resource) = 0;
};
```

### `ResourceSummary`

```cpp
struct ResourceSummary
{
    std::string uuid;   // Resource UUID (unique within namespace)
    std::string name;   // Logical name, e.g. "decoder/apache_access"
};
```

## Implementation Details

### `CrudService`

```cpp
class CrudService final : public ICrudService
{
public:
    CrudService(const std::shared_ptr<cm::store::ICMStore>& store,
                const std::shared_ptr<builder::IValidator>& validator);
    // ...
private:
    std::weak_ptr<cm::store::ICMStore> m_store;
    std::weak_ptr<builder::IValidator> m_validator;

    std::shared_ptr<cm::store::ICMStore> getStore() const;
    std::shared_ptr<builder::IValidator> getValidator() const;

    void validatePolicy(/* ... */) const;
    void validateIntegration(/* ... */) const;
    void validateAsset(/* ... */) const;

    std::shared_ptr<cm::store::ICMStoreNSReader> getNamespaceStoreView(/* ... */) const;
    std::shared_ptr<cm::store::ICMstoreNS>       getNamespaceStore(/* ... */) const;
};
```

### Anonymous-Namespace Helpers (`cmcrudservice.cpp`)

| Helper | Purpose |
|---|---|
| `assetUuidFromJson(json)` | Extracts the UUID string from a JSON asset document |
| `assetNameFromJson(json)` | Extracts the logical name string from a JSON asset document |
| `throwIfError(base::OptError)` | Converts an `OptError` into a thrown `std::runtime_error` |
| `policyFromDocument(const json::Json&)` | Converts a JSON object into `cm::store::dataType::Policy` |
| `integrationFromDocument(const json::Json&, bool requireUUID)` | Converts a JSON object into `cm::store::dataType::Integration` |
| `kvdbFromDocument(const json::Json&, bool requireUUID)` | Converts a JSON object into `cm::store::dataType::KVDB` |

### Key Flows

#### `upsertResource`

1. Receive the incoming payload as `json::Json`.
2. Branch by `ResourceType`:
   - **INTEGRATION** — convert via `integrationFromDocument()`, validate with `validateIntegration()`, then create or update.
   - **KVDB** — convert via `kvdbFromDocument()`, then create or update.
   - **DECODER / FILTER / OUTPUT** — adapt via `detail::adaptDecoder/Filter/Output()`, validate asset name prefix matches type, call `validateAsset()`, then create or update based on UUID / name existence.
3. On any failure, throw `std::runtime_error`.

#### `importNamespace` (JSON document)

1. Parse `jsonDocument` and extract `/policy` and `/resources` (kvdbs, decoders, integrations).
2. Create the namespace via `cmstore`.
3. Register a `bestEffortDelete` rollback lambda.
4. Import in strict order: KVDBs → Decoders → Filters → Outputs → Integrations → Policy.
5. Unless `force == true`, validate each resource before storing.
6. On success, return the imported `Policy`.

#### `getResourceByUUID`

1. Resolve UUID to `{name, type}` via the namespace reader.
2. Load the typed object (decoder / filter / output / integration / KVDB).
3. Serialise the typed object back to a JSON string.

#### `validateResource`

1. For **DECODER / FILTER**: adapt payload, validate name prefix, call `validator->validateAssetShallow()`.
2. For **INTEGRATION**: convert from the provided `json::Json` via `integrationFromDocument()`.
3. For **KVDB**: convert from the provided `json::Json` via `kvdbFromDocument()`.

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `cmcrud_icmcrud` | INTERFACE | `cmcrud::icmcrud` | `cmstore::icmstore` |
| `cmcrud_cmcrud` | STATIC | `cmcrud::cmcrud` | `builder::ibuilder` (public) |
| `cmcrud_mocks` | INTERFACE | `cmcrud::mocks` | `cmcrud::icmcrud`, `GTest::gmock` |
| `cmcrud_utest` | Executable | — | `cmcrud::cmcrud`, `cmstore::mocks`, `builder::mocks`, `GTest::gtest_main` |
| `cmcrud_ctest` | Executable | — | `cmcrud::cmcrud`, `cmstore::mocks`, `builder::mocks`, `GTest::gtest_main` |

## Testing

- **Unit tests** (`test/unit/`) — test `CrudService` methods with mocked `ICMStore` and `IValidator`.
- **Component tests** (`test/component/`) — broader scenarios covering import flows and resource lifecycle.
- **Mock** (`test/mocks/cmcrud/mockcmcrud.hpp`) — `MockCrudService` implements `ICrudService` with GMock macros for use by downstream consumers' tests.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `api/cmcrud` | `cmcrud::icmcrud` | HTTP API handlers that expose namespace and resource CRUD operations to external clients |
| `cmsync` | `cmcrud::icmcrud` | Content synchronization service that uses `ICrudService` to import content from the cluster |
| `main.cpp` | `cmcrud::cmcrud` | Creates the `CrudService` instance, wiring it with the store and validator |
