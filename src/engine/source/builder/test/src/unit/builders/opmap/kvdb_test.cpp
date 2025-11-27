#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/kvdb.hpp"

#include <kvdbstore/mockKvdbHandler.hpp>
#include <kvdbstore/mockKvdbManager.hpp>

using namespace builder::builders;
using namespace kvdbstore::mocks;

namespace
{

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrEq;

// Simple value stored in KVDB for KVDBGet tests.
static json::Json g_kvdbStringValue(R"("db-value")");

// Map used for KVDB bitmask decode tests: bit position -> string.
static json::Json g_bitmaskMap(R"({"0":"FLAG0","1":"FLAG1","3":"FLAG3"})");

// Extra shared JSON values used by multiple tests
static json::Json g_kvdbObjectValue(R"({"new":2})");
static json::Json g_kvdbNestedValue(R"({"a":{"added":2}})");
static json::Json g_kvdbArrayV1(R"("v1")");
static json::Json g_kvdbArrayV2(R"("v2")");
static json::Json g_kvdbNumberValue = []()
{
    json::Json j;
    j.setInt(42);
    return j;
}();

// -----------------------------------------------------------------------------
// Helpers for Transform KVDBGet
// -----------------------------------------------------------------------------
auto kvdbGetSuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Expectations:
    //  - allowedFields allows writing into "target"
    //  - schema validator does not know "ref" (no type checks enforced)
    //  - KVDB handler is obtained from manager with DB name from opArgs[0]
    //  - handler returns "db-value" for key "my-key"
    //  - final event is {"ref":"my-key","target":"db-value"}
    return [kvdbManager](const BuildersMocks& mocks) -> base::Event
    {
        // allowedFields check for target field
        EXPECT_CALL(*mocks.allowedFields, check(_, DotPath("target"))).WillOnce(Return(true));

        // Schema: we do not have definitions for "ref" or "target"
        EXPECT_CALL(*mocks.validator, hasField(_)).Times(AtLeast(1)).WillRepeatedly(Return(false));

        // getStoreNSReader is used to fetch the KVDB handler
        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        // KVDB handler for this test
        auto handler = std::make_shared<MockIKVDBHandler>();

        // Builder: KVDBGet asks the manager for the handler with DB name from opArgs[0]
        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        // Operation: KVDBGet uses key "my-key" resolved from field "ref"
        EXPECT_CALL(*handler, get(StrEq("my-key"))).WillOnce(ReturnRef(g_kvdbStringValue));

        // Expected event after operation
        auto expected = std::make_shared<json::Json>(R"({"ref":"my-key","target":"db-value"})");
        return expected;
    };
}

auto kvdbGetMissingKeyFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Failure case for operation:
    //  - key is passed as reference "ref"
    //  - event does NOT contain "ref" → fail before calling handler->get()
    //  - event should remain equal to input
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        EXPECT_CALL(*mocks.allowedFields, check(_, DotPath("target"))).WillOnce(Return(true));

        // Schema: pretend we do not have a definition for "ref"
        EXPECT_CALL(*mocks.validator, hasField(_)).Times(AtLeast(1)).WillRepeatedly(Return(false));

        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        // No handler->get() expected, failure happens when resolving the reference
        return None {};
    };
}

// -----------------------------------------------------------------------------
// Helpers for Filter KVDBMatch / KVDBNotMatch
// -----------------------------------------------------------------------------
auto kvdbMatchSuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // +kvdb_match: should return true when the key exists in KVDB.
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, contains(StrEq("key1"))).WillOnce(Return(true));

        return None {};
    };
}

auto kvdbMatchKeyNotFoundFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // +kvdb_match: should fail when the key does NOT exist in KVDB.
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, contains(StrEq("key1"))).WillOnce(Return(false));

        return None {};
    };
}

auto kvdbNotMatchSuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // +kvdb_not_match: should return true when the key does NOT exist in KVDB.
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, contains(StrEq("key1"))).WillOnce(Return(false));

        return None {};
    };
}

auto kvdbNotMatchKeyFoundFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // +kvdb_not_match: should fail when the key DOES exist in KVDB.
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, contains(StrEq("key1"))).WillOnce(Return(true));

        return None {};
    };
}

// -----------------------------------------------------------------------------
// Helpers for Transform KVDBGetArray
// -----------------------------------------------------------------------------
auto kvdbGetArraySuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - DB: k1 -> "v1", k2 -> "v2"
    //   - input event: {"keys": ["k1","k2"]}
    //   - target: "target"
    //   - result: {"keys":["k1","k2"],"target":["v1","v2"]}
    return [kvdbManager](const BuildersMocks& mocks) -> base::Event
    {
        // allowedFields allows writing into target
        EXPECT_CALL(*mocks.allowedFields, check(_, DotPath("target"))).WillOnce(Return(true));

        // Schema: by default, validator does not know any field
        EXPECT_CALL(*mocks.validator, hasField(_)).Times(AtLeast(0)).WillRepeatedly(Return(false));

        // Validate target as array (this is called unconditionally in the builder)
        EXPECT_CALL(*mocks.validator, validate(DotPath("target"), _)).WillOnce(Return(schemf::ValidationResult()));

        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        static json::Json v1(R"("v1")");
        static json::Json v2(R"("v2")");

        EXPECT_CALL(*handler, get(StrEq("k1"))).WillOnce(ReturnRef(v1));
        EXPECT_CALL(*handler, get(StrEq("k2"))).WillOnce(ReturnRef(v2));

        auto expected = std::make_shared<json::Json>(R"({"keys":["k1","k2"],"target":["v1","v2"]})");
        return expected;
    };
}

// -----------------------------------------------------------------------------
// Helpers for Transform KVDBDecodeBitmask
// -----------------------------------------------------------------------------
auto kvdbDecodeBitmaskSuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - DB has a "map" for key "bitmask-map": {"0":"FLAG0","1":"FLAG1","3":"FLAG3"}
    //   - input event: {"mask":"0xB"} // bits 0,1,3
    //   - target: "flags"
    //   - result: {"mask":"0xB","flags":["FLAG0","FLAG1","FLAG3"]}
    return [kvdbManager](const BuildersMocks& mocks) -> base::Event
    {
        // allowedFields: target array is allowed
        EXPECT_CALL(*mocks.allowedFields, check(_, DotPath("flags"))).WillOnce(Return(true));

        // Schema: assume there is no static definition for target or mask
        EXPECT_CALL(*mocks.validator, hasField(_)).Times(AtLeast(0)).WillRepeatedly(Return(false));

        EXPECT_CALL(*mocks.ctx, getStoreNSReader()).Times(AtLeast(1));

        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        // Builder: loads the map once when building the operation
        EXPECT_CALL(*handler, get(StrEq("bitmask-map"))).WillOnce(ReturnRef(g_bitmaskMap));

        auto expected = std::make_shared<json::Json>(R"({"mask":"0xB","flags":["FLAG0","FLAG1","FLAG3"]})");
        return expected;
    };
}

// -------------------------------------------------------------------------
// KVDBGet: extra expectations
// -------------------------------------------------------------------------
auto kvdbGetLiteralKeySuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - input: {}
    //   - args:  db = "test-db", key = "my-key" (literal)
    //   - DB:    "my-key" -> "db-value"
    //   - result: {"target":"db-value"}
    return [kvdbManager](const BuildersMocks& mocks) -> base::Event
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("my-key"))).WillOnce(ReturnRef(g_kvdbStringValue));

        auto expected = std::make_shared<json::Json>(R"({"target":"db-value"})");
        return expected;
    };
}

auto kvdbGetKeyNotFoundFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - DB throws std::out_of_range for the requested key
    //   - operation should fail and leave event unchanged
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("missing-key"))).WillOnce(::testing::Throw(std::out_of_range("not found")));

        return None {};
    };
}

auto kvdbGetMergeSuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - input:  {"ref":"my-key","target":{"existing":1}}
    //   - DB:     "my-key" -> {"new":2}
    //   - merge:  shallow merge into target
    //   - result: {"ref":"my-key","target":{"existing":1,"new":2}}
    return [kvdbManager](const BuildersMocks& mocks) -> base::Event
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("my-key"))).WillOnce(ReturnRef(g_kvdbObjectValue));

        auto expected = std::make_shared<json::Json>(R"({"ref":"my-key","target":{"existing":1,"new":2}})");
        return expected;
    };
}

auto kvdbGetMergeMissingTargetFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - input: {"ref":"my-key"}
    //   - doMerge = true, but target field does not exist
    //   - operation should fail and keep event unchanged
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("my-key"))).WillOnce(ReturnRef(g_kvdbObjectValue));

        return None {};
    };
}

auto kvdbGetMergeTypeMismatchFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - input: {"ref":"my-key","target":"not-object"}
    //   - DB:    "my-key" -> object
    //   - merge requires target and value to be object/array of same type
    //   - operation should fail and keep event unchanged
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("my-key"))).WillOnce(ReturnRef(g_kvdbObjectValue));

        return None {};
    };
}

auto kvdbGetMergeRecursiveSuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - input:  {"ref":"my-key","target":{"a":{"existing":1}}}
    //   - DB:     "my-key" -> {"a":{"added":2}}
    //   - recursive merge on "a"
    //   - result: {"ref":"my-key","target":{"a":{"existing":1,"added":2}}}
    return [kvdbManager](const BuildersMocks& mocks) -> base::Event
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("my-key"))).WillOnce(ReturnRef(g_kvdbNestedValue));

        auto expected = std::make_shared<json::Json>(R"({"ref":"my-key","target":{"a":{"existing":1,"added":2}}})");
        return expected;
    };
}

// -------------------------------------------------------------------------
// KVDBGetArray: extra expectations
// -------------------------------------------------------------------------
auto kvdbGetArrayExistingTargetSuccess(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - DB:   "k1" -> "v1", "k2" -> "v2"
    //   - input: {"keys":["k1","k2"],"target":["old"]}
    //   - result: {"keys":["k1","k2"],"target":["old","v1","v2"]}
    return [kvdbManager](const BuildersMocks& mocks) -> base::Event
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("k1"))).WillOnce(ReturnRef(g_kvdbArrayV1));
        EXPECT_CALL(*handler, get(StrEq("k2"))).WillOnce(ReturnRef(g_kvdbArrayV2));

        auto expected = std::make_shared<json::Json>(R"({"keys":["k1","k2"],"target":["old","v1","v2"]})");
        return expected;
    };
}

auto kvdbGetArrayMissingKeysRefFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - key array is a reference ("keys") but the field does not exist in the event
    //   - operation should fail and not call handler->get(...)
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));
        // No EXPECT_CALL on handler->get
        return None {};
    };
}

auto kvdbGetArrayHeterogeneousFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - DB returns different JSON types for the keys (string vs number)
    //   - operation should fail with "array not homogeneous" and keep event unchanged
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("k1"))).WillOnce(ReturnRef(g_kvdbArrayV1));
        EXPECT_CALL(*handler, get(StrEq("k2"))).WillOnce(ReturnRef(g_kvdbNumberValue));

        return None {};
    };
}

auto kvdbGetArrayDbErrorFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - handler->get throws std::out_of_range for one of the keys
    //   - operation should fail and keep event unchanged
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("k1"))).WillOnce(::testing::Throw(std::out_of_range("not found")));

        return None {};
    };
}

// -------------------------------------------------------------------------
// KVDBDecodeBitmask: extra expectations
// -------------------------------------------------------------------------
auto kvdbDecodeBitmaskMissingMaskFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - "mask" field is missing in the event
    //   - getMaskFn returns error and operation fails
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("bitmask-map"))).WillOnce(ReturnRef(g_bitmaskMap));

        return None {};
    };
}

auto kvdbDecodeBitmaskNonStringMaskFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - "mask" field exists but is not a string
    //   - getMaskFn returns error and operation fails
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("bitmask-map"))).WillOnce(ReturnRef(g_bitmaskMap));

        return None {};
    };
}

auto kvdbDecodeBitmaskInvalidHexFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - "mask" is a string but not a valid hex representation
    //   - std::stoul throws and getMaskFn returns error
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("bitmask-map"))).WillOnce(ReturnRef(g_bitmaskMap));

        return None {};
    };
}

auto kvdbDecodeBitmaskNoFlagsFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - "mask" = 0x0 → no bits set, no flags appended
    //   - operation fails with "empty result"
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));

        EXPECT_CALL(*handler, get(StrEq("bitmask-map"))).WillOnce(ReturnRef(g_bitmaskMap));

        return None {};
    };
}

// -------------------------------------------------------------------------
// Filter KVDBMatch / KVDBNotMatch: extra expectations
// -------------------------------------------------------------------------
auto kvdbMatchMissingFieldFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - target field does not exist
    //   - operation fails before calling contains()
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));
        return None {};
    };
}

auto kvdbMatchNonStringFieldFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - target field exists but is not a string
    //   - operation fails before calling contains()
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));
        return None {};
    };
}

auto kvdbNotMatchMissingFieldFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - target field does not exist
    //   - operation fails before calling contains()
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));
        return None {};
    };
}

auto kvdbNotMatchNonStringFieldFailure(const std::shared_ptr<MockIKVDBManager>& kvdbManager)
{
    // Scenario:
    //   - target field exists but is not a string
    //   - operation fails before calling contains()
    return [kvdbManager](const BuildersMocks& mocks) -> None
    {
        auto handler = std::make_shared<MockIKVDBHandler>();

        EXPECT_CALL(*kvdbManager, getKVDBHandler(Ref(*mocks.nsReader), StrEq("test-db"))).WillOnce(Return(handler));
        return None {};
    };
}

} // namespace

// ============================================================================
// TransformOperationTest for KVDB helpers
// ============================================================================
namespace transformoperatestest
{

INSTANTIATE_TEST_SUITE_P(KVDBGet,
                         TransformOperationTest,
                         testing::Values(
                             // KVDBGet: target is set from KVDB value by key resolved from reference
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"ref":"my-key"})",
                                                   getOpBuilderKVDBGet(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("ref"),
                                                   },
                                                   SUCCESS(kvdbGetSuccess(kvdbManager)));
                             }(),
                             // KVDBGet: failure when reference for key does not exist in the event
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"other":"field"})",
                                                   getOpBuilderKVDBGet(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("ref"),
                                                   },
                                                   FAILURE(kvdbGetMissingKeyFailure(kvdbManager)));
                             }(),
                             // KVDBGet: success with literal key value
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({})",
                                                   getOpBuilderKVDBGet(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeValue(R"("my-key")"),
                                                   },
                                                   SUCCESS(kvdbGetLiteralKeySuccess(kvdbManager)));
                             }(),
                             // KVDBGet: runtime failure when DB does not contain the key
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"ref":"missing-key"})",
                                                   getOpBuilderKVDBGet(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("ref"),
                                                   },
                                                   FAILURE(kvdbGetKeyNotFoundFailure(kvdbManager)));
                             }(),
                             // KVDBGetMerge: shallow merge of object values
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"ref":"my-key","target":{"existing":1}})",
                                                   getOpBuilderKVDBGetMerge(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("ref"),
                                                   },
                                                   SUCCESS(kvdbGetMergeSuccess(kvdbManager)));
                             }(),
                             // KVDBGetMerge: failure when target field is missing
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"ref":"my-key"})",
                                                   getOpBuilderKVDBGetMerge(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("ref"),
                                                   },
                                                   FAILURE(kvdbGetMergeMissingTargetFailure(kvdbManager)));
                             }(),
                             // KVDBGetMerge: failure when target type mismatches DB value
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"ref":"my-key","target":"not-object"})",
                                                   getOpBuilderKVDBGetMerge(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("ref"),
                                                   },
                                                   FAILURE(kvdbGetMergeTypeMismatchFailure(kvdbManager)));
                             }(),
                             // KVDBGetMergeRecursive: recursive merge on nested object
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"ref":"my-key","target":{"a":{"existing":1}}})",
                                                   getOpBuilderKVDBGetMergeRecursive(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("ref"),
                                                   },
                                                   SUCCESS(kvdbGetMergeRecursiveSuccess(kvdbManager)));
                             }()),
                         testNameFormatter<TransformOperationTest>("KVDBGet"));

INSTANTIATE_TEST_SUITE_P(KVDBGetArray,
                         TransformOperationTest,
                         testing::Values(
                             // kvdb_get_array: collect values from multiple keys into an array target
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"keys":["k1","k2"]})",
                                                   getOpBuilderKVDBGetArray(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("keys"),
                                                   },
                                                   SUCCESS(kvdbGetArraySuccess(kvdbManager)));
                             }(),
                             // kvdb_get_array: append to an existing target array
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"keys":["k1","k2"],"target":["old"]})",
                                                   getOpBuilderKVDBGetArray(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("keys"),
                                                   },
                                                   SUCCESS(kvdbGetArrayExistingTargetSuccess(kvdbManager)));
                             }(),
                             // kvdb_get_array: failure when key array reference is missing in the event
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({})",
                                                   getOpBuilderKVDBGetArray(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("keys"),
                                                   },
                                                   FAILURE(kvdbGetArrayMissingKeysRefFailure(kvdbManager)));
                             }(),
                             // kvdb_get_array: failure when DB values are not homogeneous
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"keys":["k1","k2"]})",
                                                   getOpBuilderKVDBGetArray(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("keys"),
                                                   },
                                                   FAILURE(kvdbGetArrayHeterogeneousFailure(kvdbManager)));
                             }(),
                             // kvdb_get_array: failure when getting one of the keys throws
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"keys":["k1"]})",
                                                   getOpBuilderKVDBGetArray(kvdbManager),
                                                   "target",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeRef("keys"),
                                                   },
                                                   FAILURE(kvdbGetArrayDbErrorFailure(kvdbManager)));
                             }()),
                         testNameFormatter<TransformOperationTest>("KVDBGetArray"));

INSTANTIATE_TEST_SUITE_P(KVDBDecodeBitmask,
                         TransformOperationTest,
                         testing::Values(
                             // kvdb_decode_bitmask: decode flags from a KVDB map using a hexadecimal bitmask
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"mask":"0xB"})",
                                                   getOpBuilderHelperKVDBDecodeBitmask(kvdbManager),
                                                   "flags",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeValue(R"("bitmask-map")"),
                                                       makeRef("mask"),
                                                   },
                                                   SUCCESS(kvdbDecodeBitmaskSuccess(kvdbManager)));
                             }(),
                             // kvdb_decode_bitmask: failure when mask field is missing
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({})",
                                                   getOpBuilderHelperKVDBDecodeBitmask(kvdbManager),
                                                   "flags",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeValue(R"("bitmask-map")"),
                                                       makeRef("mask"),
                                                   },
                                                   FAILURE(kvdbDecodeBitmaskMissingMaskFailure(kvdbManager)));
                             }(),
                             // kvdb_decode_bitmask: failure when mask field is not a string
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"mask":123})",
                                                   getOpBuilderHelperKVDBDecodeBitmask(kvdbManager),
                                                   "flags",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeValue(R"("bitmask-map")"),
                                                       makeRef("mask"),
                                                   },
                                                   FAILURE(kvdbDecodeBitmaskNonStringMaskFailure(kvdbManager)));
                             }(),
                             // kvdb_decode_bitmask: failure when mask is not valid hexadecimal
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"mask":"ZZ"})",
                                                   getOpBuilderHelperKVDBDecodeBitmask(kvdbManager),
                                                   "flags",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeValue(R"("bitmask-map")"),
                                                       makeRef("mask"),
                                                   },
                                                   FAILURE(kvdbDecodeBitmaskInvalidHexFailure(kvdbManager)));
                             }(),
                             // kvdb_decode_bitmask: failure when mask does not produce any flag
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return TransformT(R"({"mask":"0x0"})",
                                                   getOpBuilderHelperKVDBDecodeBitmask(kvdbManager),
                                                   "flags",
                                                   std::vector<OpArg> {
                                                       makeValue(R"("test-db")"),
                                                       makeValue(R"("bitmask-map")"),
                                                       makeRef("mask"),
                                                   },
                                                   FAILURE(kvdbDecodeBitmaskNoFlagsFailure(kvdbManager)));
                             }()),
                         testNameFormatter<TransformOperationTest>("KVDBDecodeBitmask"));

} // namespace transformoperatestest

// ============================================================================
// FilterOperationTest for KVDB helpers (match / not_match)
// ============================================================================
namespace filteroperatestest
{

INSTANTIATE_TEST_SUITE_P(KVDBMatch,
                         FilterOperationTest,
                         testing::Values(
                             // +kvdb_match: returns true when the key exists in KVDB
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({"field":"key1"})",
                                                getOpBuilderKVDBMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                SUCCESS(kvdbMatchSuccess(kvdbManager)));
                             }(),
                             // +kvdb_match: returns false when the key does not exist in KVDB
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({"field":"key1"})",
                                                getOpBuilderKVDBMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                FAILURE(kvdbMatchKeyNotFoundFailure(kvdbManager)));
                             }(),
                             // +kvdb_match: failure when field is missing
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({})",
                                                getOpBuilderKVDBMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                FAILURE(kvdbMatchMissingFieldFailure(kvdbManager)));
                             }(),
                             // +kvdb_match: failure when field is not a string
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({"field":123})",
                                                getOpBuilderKVDBMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                FAILURE(kvdbMatchNonStringFieldFailure(kvdbManager)));
                             }()),
                         testNameFormatter<FilterOperationTest>("KVDBMatch"));

INSTANTIATE_TEST_SUITE_P(KVDBNotMatch,
                         FilterOperationTest,
                         testing::Values(
                             // +kvdb_not_match: returns true when the key does not exist in KVDB
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({"field":"key1"})",
                                                getOpBuilderKVDBNotMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                SUCCESS(kvdbNotMatchSuccess(kvdbManager)));
                             }(),
                             // +kvdb_not_match: returns false when the key exists in KVDB
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({"field":"key1"})",
                                                getOpBuilderKVDBNotMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                FAILURE(kvdbNotMatchKeyFoundFailure(kvdbManager)));
                             }(),
                             // +kvdb_not_match: failure when field is missing
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({})",
                                                getOpBuilderKVDBNotMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                FAILURE(kvdbNotMatchMissingFieldFailure(kvdbManager)));
                             }(),
                             // +kvdb_not_match: failure when field is not a string
                             []()
                             {
                                 auto kvdbManager = std::make_shared<MockIKVDBManager>();
                                 return FilterT(R"({"field":123})",
                                                getOpBuilderKVDBNotMatch(kvdbManager),
                                                "field",
                                                std::vector<OpArg> {
                                                    makeValue(R"("test-db")"),
                                                },
                                                FAILURE(kvdbNotMatchNonStringFieldFailure(kvdbManager)));
                             }()),
                         testNameFormatter<FilterOperationTest>("KVDBNotMatch"));

} // namespace filteroperatestest
