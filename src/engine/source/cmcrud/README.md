# cmcrud

## Overview

The **cmcrud** module is the **CRUD service layer** for the Wazuh engine's Content Manager. It sits between the API handlers (`api/cmcrud`), the content synchronization service (`cmsync`) and the underlying `cmstore`, mediating create / read / update / delete operations on namespaces, policies, and resources (decoders, filters, outputs, integrations, KVDBs).

Before a mutation reaches the store, `cmcrud` receives a structured `json::Json` payload, applies type-specific adaptations (canonical field ordering for assets), and delegates structural validation to `builder::IValidator` (the `builder::Builder` instance in production). The bulk import paths can skip that validation (`force` / `softValidation`); see [Namespace Import](#namespace-import).

The routes that reach this module (`/_internal/content/*` and the public `/content/validate/*` routes) are documented for operators in the engine's [private API reference](../../../../docs/ref/modules/engine/private-api-reference.md) and [public API reference](../../../../docs/ref/modules/engine/public-api-reference.md).

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

The single-resource mutations (`upsertPolicy`, `upsertResource`) always validate before writing. Depending on the resource type `CrudService` calls:

| Resource Type | Validation Path |
|---|---|
| **Policy** | `IValidator::softPolicyValidate()` |
| **Integration** | `IValidator::softIntegrationValidate()` |
| **Asset** (decoder / filter / output) | `IValidator::validateAsset()` |
| **KVDB** | Parsed via `cm::store::dataType::KVDB::fromJson()` (structural check only) |

A failed `base::OptError` from the validator is turned into `std::runtime_error` by `throwIfError()`. On the import paths the `force` / `softValidation` flag skips the validator calls; the structural checks (adapter, name prefix, UUID, `fromJson`) still run.

### Asset Adaptation

Before storing an asset, its JSON representation is run through a type-specific *adapter* from `cmstore/detail.hpp`:

- `cm::store::detail::adaptDecoder()` — decoders
- `cm::store::detail::adaptFilter()` — filters
- `cm::store::detail::adaptOutput()` — outputs

Each adapter rebuilds the document with its known keys in a fixed order (keys it does not know are dropped), checks that `name` has exactly three parts `<type>/<name>/<version>` with the matching prefix, and requires a boolean `enabled`. This gives a deterministic serialisation regardless of the order in which the caller supplied the fields.

### Namespace Import

Import only targets a **new** namespace: both overloads throw if `nsId` already exists. Resources are ingested in a fixed order so that references resolve:

1. **KVDBs**
2. **Decoders**
3. **Filters**
4. **Outputs** (JSON-document overload only)
5. **Integrations**
6. **Policy**

Two overloads exist:

| Overload | Input | Caller | Rollback |
|---|---|---|---|
| `importNamespace(nsId, jsonDocument, originSpace, force)` | One JSON document `{"policy": {…}, "resources": {"kvdbs", "decoders", "filters", "outputs", "integrations"}}` | `api/cmcrud`: `namespaceImport`, and `policyValidate` (`POST /content/validate/policy`) into a temporary namespace with `force=true` | Internal: the `bestEffortDelete` lambda deletes the namespace if any step fails after it was created |
| `importNamespace(nsId, kvdbs, decoders, filters, integrations, policy, softValidation)` | Pre-parsed component vectors (no outputs) | `cmsync` (always `softValidation=true`) | None internally; `cmsync` deletes the namespace itself when the call throws |

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
│   └── cmcrudservice.cpp           # Implementation
└── test/
    ├── mocks/cmcrud/
    │   └── mockcmcrud.hpp          # GMock mock (MockCrudService)
    └── src/
        ├── unit/cmcrudservice_test.cpp
        └── component/cmcrud_test.cpp
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
                    std::string_view originSpace,
                    bool force) = 0;

    virtual void
    importNamespace(const cm::store::NamespaceId& nsId,
                    const std::vector<json::Json>& kvdbs,
                    const std::vector<json::Json>& decoders,
                    const std::vector<json::Json>& filters,
                    const std::vector<json::Json>& integrations,
                    const json::Json& policy,
                    bool softValidation) = 0;

    // ── Policy ─────────────────────────────────────────────
    virtual void upsertPolicy(const cm::store::NamespaceId& nsId,
                              const json::Json& policy) = 0;
    virtual void deletePolicy(const cm::store::NamespaceId& nsId) = 0;

    // ── Generic Resources ──────────────────────────────────
    virtual std::vector<ResourceSummary>
    listResources(const cm::store::NamespaceId& nsId,
                  cm::store::ResourceType type) const = 0;

    virtual json::Json
    getResourceByUUID(const cm::store::NamespaceId& nsId,
                      const std::string& uuid) const = 0;

    virtual void
    upsertResource(const cm::store::NamespaceId& nsId,
                   cm::store::ResourceType type,
                   const json::Json& resource) = 0;

    virtual void
    deleteResourceByUUID(const cm::store::NamespaceId& nsId,
                         const std::string& uuid) = 0;

    virtual void
    validateResource(cm::store::ResourceType type,
                     const json::Json& payload) = 0;
};
```

All methods signal failure by throwing `std::runtime_error`, its message prefixed with the operation (`Failed to upsert resource of type '…' in namespace '…': …`).

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

    void validatePolicy(nsReader, policy) const;
    void validateIntegration(nsReader, integration) const;
    void validateAsset(nsReader, assetJson) const;

    std::shared_ptr<cm::store::ICMStoreNSReader> getNamespaceStoreView(nsId) const;
    std::shared_ptr<cm::store::ICMstoreNS>       getNamespaceStore(nsId) const;
};
```

The constructor throws `std::invalid_argument` on a null store or validator. Dependencies are held as `std::weak_ptr`; `getStore()` / `getValidator()` lock them and throw `std::runtime_error` (`CMStore is no longer available`, `Validator is no longer available`) once the owner has released them. `getNamespaceStore*()` throw `Namespace '<ns>' does not exist` when the store returns no handle.

### Anonymous-Namespace Helpers (`cmcrudservice.cpp`)

| Helper | Purpose |
|---|---|
| `assetUuidFromJson(json, name)` | Reads `/id`; throws if missing, empty or not a valid resource id (`base::utils::generators::isValidResourceId`) |
| `assetNameFromJson(json)` | Reads `/name` as `base::Name`; throws if missing or empty |
| `throwIfError(base::OptError, context)` | Converts an `OptError` into a thrown `std::runtime_error` |
| `policyFromDocument(const json::Json&)` | `cm::store::dataType::Policy::fromJson` |
| `integrationFromDocument(const json::Json&, bool requireUUID)` | `cm::store::dataType::Integration::fromJson` |
| `kvdbFromDocument(const json::Json&, bool requireUUID)` | `cm::store::dataType::KVDB::fromJson` |
| `existsByUUIDWithType(nsReader, uuid, type)` | True if the UUID exists with this type; throws `UUID '…' already belongs to <type> '…'` if it belongs to another type (the store updates by UUID whatever owns it) |

### Key Flows

#### `upsertResource`

1. Resolve the namespace (`getNamespaceStore`).
2. Branch by `ResourceType`:
   - **INTEGRATION** — `integrationFromDocument(…, requireUUID=false)`, `validateIntegration()`, then `updateResourceByUUID` if `existsByUUIDWithType()` else `createResource`.
   - **KVDB** — `kvdbFromDocument(…, requireUUID=false)` (no validator call), then update by UUID or create, same rule.
   - **DECODER / FILTER / OUTPUT** — adapt via `adaptDecoder/Filter/Output()`, check the name prefix matches the type, `validateAsset()`, then `updateResourceByName` if `assetExistsByName()` else `createResource`.
3. On any failure, throw `std::runtime_error`.

#### `importNamespace` (JSON document)

1. Reject an existing `nsId`.
2. Parse `jsonDocument`; the root must have exactly the two object keys `policy` and `resources`.
3. Create the namespace; from here any exception triggers `bestEffortDelete` (a failed rollback is logged as a warning).
4. Import `/resources/kvdbs`, `decoders`, `filters`, `outputs`, `integrations` in that order (an absent array is skipped). Integrations and KVDBs need a UUID and a valid name part; assets need `/id`, a valid name and a matching prefix.
5. Unless `force == true`, validate each integration, asset and the policy.
6. Set the policy's origin space when `originSpace` is not empty, upsert it, and return the stored `Policy`.

#### `getResourceByUUID`

1. Resolve the UUID to `{name, type}` via the namespace reader.
2. Load the typed object (integration / KVDB via their `toJson()`, decoder / filter / output via `getAssetByUUID`).
3. Return it as `json::Json`.

#### `validateResource`

No namespace is involved.

1. **DECODER / FILTER**: adapt the payload, require `/id`, check the name prefix, call `validator->validateAssetShallow()`.
2. **INTEGRATION**: `Integration::fromJson(…, requireUUID=true)` and a valid name part.
3. **KVDB**: `KVDB::fromJson(…, requireUUID=true)` and a valid name part.
4. Any other type (including **OUTPUT**) throws `Unsupported resource type`. The `POST /content/validate/resource` handler never reaches this case: it answers `Unsupported value for /type` for `output` as for an unknown type.

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `cmcrud_icmcrud` | INTERFACE | `cmcrud::icmcrud` | `base`, `cmstore::icmstore` |
| `cmcrud_cmcrud` | STATIC | `cmcrud::cmcrud` | `cmcrud::icmcrud`, `builder::ibuilder` (public); `yml` (private) |
| `cmcrud_mocks` | INTERFACE | `cmcrud::mocks` | `cmcrud::icmcrud`, `GTest::gmock` |
| `cmcrud_utest` | Executable | — | `cmcrud::cmcrud`, `cmcrud::mocks`, `cmstore::mocks`, `builder::mocks`, `GTest::gtest_main`, `GTest::gmock` |
| `cmcrud_ctest` | Executable | — | same as `cmcrud_utest` |

The mocks and test executables exist only when `ENGINE_BUILD_TEST` is on.

## Testing

- **Unit tests** (`test/src/unit/cmcrudservice_test.cpp`) — `CrudService` methods with mocked `ICMStore` and `IValidator`.
- **Component tests** (`test/src/component/cmcrud_test.cpp`) — import flows and resource lifecycle, still over the mocks.
- **Mock** (`test/mocks/cmcrud/mockcmcrud.hpp`) — `MockCrudService` implements `ICrudService` with GMock macros for downstream consumers' tests (`api/cmcrud`, `cmsync`).

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `api/cmcrud` | `cmcrud::icmcrud` | API handlers that expose namespace and resource CRUD, namespace import and resource validation |
| `cmsync` | `cmcrud::icmcrud` | Content synchronization service that imports each space downloaded from `wazuh-indexer` |
| `main.cpp` | `cmcrud::cmcrud` | Creates the `CrudService` with `cmStore` and the `builder::Builder` as validator, and hands it to `cmsync` and the API handlers |
