#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>
#include <base/json.hpp>
#include <base/result.hpp>
#include <iockvdb/iManager.hpp>
#include <iockvdb/mockManager.hpp>

#include "builders/enrichment/enrichment.hpp"

using namespace builder::builders::enrichment;
using namespace testing;

namespace
{

// ─────────────────────────────────────────────────────────────────────────────
// Expression evaluator
// ─────────────────────────────────────────────────────────────────────────────
bool evalExpression(const base::Expression& expression, const base::Event& event)
{
    if (expression == nullptr)
        return true;

    if (expression->isTerm())
    {
        auto term = expression->getPtr<base::Term<base::EngineOp>>();
        return term->getFn()(event).success();
    }

    if (expression->isChain())
    {
        auto op = expression->getPtr<base::Chain>();
        for (auto& operand : op->getOperands()) evalExpression(operand, event);
        return true;
    }

    if (expression->isImplication())
    {
        auto op = expression->getPtr<base::Implication>();
        if (evalExpression(op->getOperands()[0], event))
            return evalExpression(op->getOperands()[1], event);
        return false;
    }

    if (expression->isAnd())
    {
        auto op = expression->getPtr<base::And>();
        for (auto& operand : op->getOperands())
        {
            if (!evalExpression(operand, event))
                return false;
        }
        return true;
    }

    if (expression->isOr())
    {
        auto op = expression->getPtr<base::Or>();
        for (auto& operand : op->getOperands())
        {
            if (evalExpression(operand, event))
                return true;
        }
        return false;
    }

    if (expression->isBroadcast())
    {
        auto op = expression->getPtr<base::Broadcast>();
        for (auto& operand : op->getOperands()) evalExpression(operand, event);
        return true;
    }

    return true;
}

json::Json makeHashConfig(const std::string& field)
{
    auto doc = fmt::format(R"({{"hash_md5": {{"sources": ["{}"]}}}})", field);
    return json::Json {doc.c_str()};
}

json::Json makeMultiSourceHashConfig(const std::vector<std::string>& fields)
{
    std::string sources;
    for (size_t i = 0; i < fields.size(); ++i)
    {
        sources += fmt::format(R"("{}")", fields[i]);
        if (i + 1 < fields.size())
            sources += ", ";
    }
    auto doc = fmt::format(R"({{"hash_md5": {{"sources": [{}]}}}})", sources);
    return json::Json {doc.c_str()};
}

json::Json makeConnectionConfig(const std::string& ipField, const std::string& portField)
{
    auto doc = fmt::format(
        R"({{"connection": {{"sources": [{{"ip_field": "{}", "port_field": "{}"}}]}}}})", ipField, portField);
    return json::Json {doc.c_str()};
}

base::Event makeEvent(const std::string& jsonStr)
{
    return std::make_shared<json::Json>(jsonStr.c_str());
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Test: Build an IOC enrichment operation using a valid configuration
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, BuildValidConfiguration)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(false);

    ASSERT_NE(expr, nullptr);
    EXPECT_FALSE(name.empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Build a lookup key from a single source field
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, LookupKeySingleSource)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    // The KVDB should be queried with the lowercase value of the field
    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_hashes_md5"), std::string_view("abc123def")))
        .WillOnce(Return(std::optional<json::Json>(json::Json(R"({"type": "md5"})"))));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent(R"({"file": {"hash": {"md5": "ABC123DEF"}}})");
    evalExpression(expr, event);

    // Verify enrichment was appended
    EXPECT_TRUE(event->exists("/wazuh/threat/enrichments"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Build a lookup key from multiple source fields
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, LookupKeyMultipleSources)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeMultiSourceHashConfig({"file.hash.md5", "file.hash.sha1"});

    // Each source becomes an independent lookup
    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_hashes_md5"), _)).WillRepeatedly(Return(std::nullopt));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent(R"({"file": {"hash": {"md5": "abc", "sha1": "def"}}})");
    evalExpression(expr, event);

    // No match found so no enrichments
    EXPECT_FALSE(event->exists("/wazuh/threat/enrichments"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Build a lookup key for connection using IP and port fields
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, LookupKeyConnection)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeConnectionConfig("source.ip", "source.port");

    // Connection key is "ip:port" lowercase
    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_connections"), std::string_view("192.168.1.1:8080")))
        .WillOnce(Return(std::optional<json::Json>(json::Json(R"({"type": "connection"})"))));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "connection");
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent(R"({"source": {"ip": "192.168.1.1", "port": 8080}})");
    evalExpression(expr, event);

    EXPECT_TRUE(event->exists("/wazuh/threat/enrichments"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Handle an event where one of the configured source fields is missing
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, MissingSourceField)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(false);

    // Event without the hash field
    auto event = makeEvent(R"({"file": {"name": "test.txt"}})");
    evalExpression(expr, event);

    EXPECT_FALSE(event->exists("/wazuh/threat/enrichments"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Handle a KVDB lookup with no match
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, KvdbLookupNoMatch)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_hashes_md5"), _)).WillOnce(Return(std::nullopt));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent(R"({"file": {"hash": {"md5": "deadbeef"}}})");
    evalExpression(expr, event);

    EXPECT_FALSE(event->exists("/wazuh/threat/enrichments"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Enrich an event when the KVDB lookup returns IOC data
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, KvdbLookupMatch)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    json::Json iocData(R"({"type": "file", "description": "Known malware hash"})");
    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_hashes_md5"), std::string_view("deadbeef")))
        .WillOnce(Return(std::optional<json::Json>(iocData)));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(false);

    auto event = makeEvent(R"({"file": {"hash": {"md5": "DEADBEEF"}}})");
    evalExpression(expr, event);

    // Verify enrichment array exists and has expected structure
    EXPECT_TRUE(event->exists("/wazuh/threat/enrichments"));
    EXPECT_TRUE(event->exists("/wazuh/threat/enrichments/0/indicator"));
    EXPECT_TRUE(event->exists("/wazuh/threat/enrichments/0/matched/field"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Reject an unsupported IOC type
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, UnsupportedIocType)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    // Use a completely invalid JSON config with an invalid type
    json::Json config(R"({"invalid_type": {"sources": ["field.a"]}})");

    EXPECT_THROW(getIocEnrichmentBuilder(mockKvdb, config, "invalid_type"), std::runtime_error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Reject a configuration without sources
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, MissingSources)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    // Config has the type key but no sources array
    json::Json config(R"({"hash_md5": {}})");

    EXPECT_THROW(getIocEnrichmentBuilder(mockKvdb, config, "hash_md5"), std::runtime_error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Reject an incomplete connection configuration
// ─────────────────────────────────────────────────────────────────────────────
TEST(IocEnrichmentTest, IncompleteConnectionConfig)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    // Connection source missing port_field
    json::Json config(R"({"connection": {"sources": [{"ip_field": "source.ip"}]}})");

    EXPECT_THROW(getIocEnrichmentBuilder(mockKvdb, config, "connection"), std::runtime_error);
}

// =============================================================================
// Tests with isTestMode=true (trace messages in IOC enrichment)
// =============================================================================

TEST(IocEnrichmentTest, TestModeIocMatchFound)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    json::Json iocData(R"({"type": "file", "description": "Known malware"})");
    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_hashes_md5"), std::string_view("deadbeef")))
        .WillOnce(Return(std::optional<json::Json>(iocData)));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent(R"({"file": {"hash": {"md5": "DEADBEEF"}}})");
    evalExpression(expr, event);

    EXPECT_TRUE(event->exists("/wazuh/threat/enrichments"));
}

TEST(IocEnrichmentTest, TestModeIocNotFound)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_hashes_md5"), _)).WillOnce(Return(std::nullopt));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent(R"({"file": {"hash": {"md5": "deadbeef"}}})");
    evalExpression(expr, event);

    EXPECT_FALSE(event->exists("/wazuh/threat/enrichments"));
}

TEST(IocEnrichmentTest, TestModeMissingSourceField)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeHashConfig("file.hash.md5");

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "hash_md5");
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent(R"({"file": {"name": "test.txt"}})");
    evalExpression(expr, event);

    EXPECT_FALSE(event->exists("/wazuh/threat/enrichments"));
}

TEST(IocEnrichmentTest, TestModeConnectionMatchFound)
{
    auto mockKvdb = std::make_shared<ioc::kvdb::MockKVDBManager>();
    auto config = makeConnectionConfig("source.ip", "source.port");

    EXPECT_CALL(*mockKvdb, get(std::string_view("ioc_connections"), std::string_view("10.0.0.1:443")))
        .WillOnce(Return(std::optional<json::Json>(json::Json(R"({"type": "connection"})"))));

    auto enrichBuilder = getIocEnrichmentBuilder(mockKvdb, config, "connection");
    auto [expr, name] = enrichBuilder(true);

    auto event = makeEvent(R"({"source": {"ip": "10.0.0.1", "port": 443}})");
    evalExpression(expr, event);

    EXPECT_TRUE(event->exists("/wazuh/threat/enrichments"));
}
