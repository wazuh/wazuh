#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <builder/mockValidator.hpp>
#include <cmstore/mockcmstore.hpp>

#include <cmcrud/cmcontentvalidator.hpp>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace cm::crud::test
{

using builder::mocks::MockValidator;
using cm::crud::ContentValidator;
using cm::store::MockICMStoreNSReader;
using cm::store::NamespaceId;

// ---------------------------------------------------------------------
// Helpers to build sample objects (Policy, Integration, Asset, KVDB)
// ---------------------------------------------------------------------

static cm::store::dataType::Policy makeSamplePolicy()
{
    json::Json policyJson {R"(
    {
      "type": "policy",
      "title": "Development 0.0.1",
      "default_parent": "decoder/integration/0",
      "root_decoder": "decoder/wazuh-core-message/0",
      "integrations": [
        "42e28392-4f5e-473d-89e8-c9030e6fedc2",
        "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
      ]
    })"};

    return cm::store::dataType::Policy::fromJson(policyJson);
}

static cm::store::dataType::Integration makeSampleIntegration()
{
    json::Json integrationJson {R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "title": "windows",
      "enabled": true,
      "category": "ossec",
      "decoders": [
        "85853f26-5779-469b-86c4-c47ee7d400b4"
      ],
      "kvdbs": []
    })"};

    return cm::store::dataType::Integration::fromJson(integrationJson);
}

static cm::store::dataType::KVDB makeSampleKVDB()
{
    json::Json kvdbJson {R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "title": "windows_kerberos_status_code_to_code_name",
      "content": {
        "0x0": "KDC_ERR_NONE",
        "0x1": "KDC_ERR_NAME_EXP"
      },
      "enabled": true
    })"};

    return cm::store::dataType::KVDB::fromJson(kvdbJson);
}

static json::Json makeSampleAssetJson()
{
    json::Json assetJson {R"(
    {
      "name": "decoder/syslog/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "metadata": { "module": "syslog" }
    })"};

    return assetJson;
}

// ---------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------

TEST(ContentValidator_Unit, Construction_NullBuilderValidatorThrows)
{
    std::shared_ptr<builder::IValidator> nullPtr;
    EXPECT_THROW(ContentValidator validator(nullPtr), std::invalid_argument);
}

TEST(ContentValidator_Unit, Construction_ValidBuilderValidatorSucceeds)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    EXPECT_NO_THROW(ContentValidator validator(builderValidator));
}

// ---------------------------------------------------------------------
// validatePolicy
// ---------------------------------------------------------------------

TEST(ContentValidator_Unit, ValidatePolicy_SuccessWhenBuilderReturnsNoError)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    ContentValidator validator {builderValidator};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();
    NamespaceId nsId {"dev"};
    ON_CALL(*nsReader, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));

    auto policy = makeSamplePolicy();

    // We only care that the builder is called and returns no error
    EXPECT_CALL(*builderValidator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(validator.validatePolicy(nsReader, policy));
}

TEST(ContentValidator_Unit, ValidatePolicy_ErrorIsWrappedWithNamespace)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    ContentValidator validator {builderValidator};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();
    NamespaceId nsId {"dev"};
    ON_CALL(*nsReader, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));

    auto policy = makeSamplePolicy();

    base::OptError err = base::Error {"policy failed"};

    EXPECT_CALL(*builderValidator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(err));

    try
    {
        validator.validatePolicy(nsReader, policy);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, ::testing::HasSubstr("Policy validation failed in namespace 'dev'"));
        EXPECT_THAT(msg, ::testing::HasSubstr("policy failed"));
    }
}

// ---------------------------------------------------------------------
// validateIntegration
// ---------------------------------------------------------------------

TEST(ContentValidator_Unit, ValidateIntegration_SuccessWhenBuilderReturnsNoError)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    ContentValidator validator {builderValidator};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();
    NamespaceId nsId {"dev"};
    ON_CALL(*nsReader, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    auto integration = makeSampleIntegration();

    EXPECT_CALL(*builderValidator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(validator.validateIntegration(nsReader, integration));
}

TEST(ContentValidator_Unit, ValidateIntegration_ErrorIsWrappedWithName)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    ContentValidator validator {builderValidator};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();
    NamespaceId nsId {"dev"};
    ON_CALL(*nsReader, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    auto integration = makeSampleIntegration(); // title "windows"

    base::OptError err = base::Error {"integration failed"};

    EXPECT_CALL(*builderValidator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(err));

    try
    {
        validator.validateIntegration(nsReader, integration);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, ::testing::HasSubstr("Integration validation failed for 'windows'"));
        EXPECT_THAT(msg, ::testing::HasSubstr("integration failed"));
    }
}

// ---------------------------------------------------------------------
// validateKVDB (currently no-op in ContentValidator)
// ---------------------------------------------------------------------

TEST(ContentValidator_Unit, ValidateKVDB_DoesNotThrow)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    ContentValidator validator {builderValidator};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();
    auto kvdb = makeSampleKVDB();

    EXPECT_NO_THROW(validator.validateKVDB(nsReader, kvdb));
}

// ---------------------------------------------------------------------
// validateAsset
// ---------------------------------------------------------------------

TEST(ContentValidator_Unit, ValidateAsset_SuccessWhenBuilderReturnsNoError)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    ContentValidator validator {builderValidator};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();
    auto assetJson = makeSampleAssetJson();

    EXPECT_CALL(*builderValidator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(validator.validateAsset(nsReader, assetJson));
}

TEST(ContentValidator_Unit, ValidateAsset_ErrorIsForwardedAsRuntimeError)
{
    auto builderValidator = std::make_shared<NiceMock<MockValidator>>();
    ContentValidator validator {builderValidator};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();
    NamespaceId nsId {"dev"};
    ON_CALL(*nsReader, getNamespaceId()).WillByDefault(::testing::ReturnRef(nsId));

    auto assetJson = makeSampleAssetJson();

    base::OptError err = base::Error {"asset validation failed"};

    EXPECT_CALL(*builderValidator, validateAsset(_, _)).Times(1).WillOnce(Return(err));

    try
    {
        validator.validateAsset(nsReader, assetJson);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, ::testing::HasSubstr("asset validation failed"));
    }
}

} // namespace cm::crud::test
