#include <chrono>
#include <gtest/gtest.h>
#include <json.hpp>

#include <sca_checksum.hpp>
#include <sca_policy_loader.hpp>

class SCAChecksumIntegrationTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            sampleCheck = {{"id", "integration_check_001"},
                {"policy_id", "integration_policy_001"},
                {"name", "Integration Test Check"},
                {"description", "Check for integration testing"},
                {"rationale", "Ensure integration works"},
                {"remediation", "Fix any integration issues"},
                {"refs", "https://integration.test"},
                {"condition", "all"},
                {"compliance", "TEST_STANDARD"},
                {"rules", "file:/etc/test -> exists"}
            };
        }

        nlohmann::json sampleCheck;
};

class SCAChecksumTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Sample check data for testing
            sampleCheckData = {{"id", "test_check_001"},
                {"policy_id", "test_policy_001"},
                {"name", "Test Security Check"},
                {"description", "This is a test security check"},
                {"rationale", "Testing rationale for security"},
                {"remediation", "Steps to remediate the issue"},
                {"refs", "https://example.com/ref1,https://example.com/ref2"},
                {"condition", "all"},
                {"compliance", "PCI_DSS_3.2.1"},
                {"rules", "file:$SSH_CONFIG -> exists"}
            };

            minimalCheckData = {{"id", "minimal_check"}, {"policy_id", "minimal_policy"}};

            emptyCheckData = nlohmann::json::object();
        }

        nlohmann::json sampleCheckData;
        nlohmann::json minimalCheckData;
        nlohmann::json emptyCheckData;
};

TEST_F(SCAChecksumTest, CalculateChecksumFromJSON_ValidData_ReturnsNonEmptyString)
{
    std::string checksum = sca::calculateChecksum(sampleCheckData);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40); // SHA1 produces 40 character hex string
}

TEST_F(SCAChecksumTest, CalculateChecksumFromJSON_MinimalData_ReturnsNonEmptyString)
{
    std::string checksum = sca::calculateChecksum(minimalCheckData);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40);
}

TEST_F(SCAChecksumTest, CalculateChecksumFromJSON_EmptyData_ReturnsNonEmptyString)
{
    std::string checksum = sca::calculateChecksum(emptyCheckData);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40);
}

TEST_F(SCAChecksumTest, CalculateChecksumFromFields_ValidData_ReturnsNonEmptyString)
{
    std::string checksum = sca::calculateChecksum("test_check_001",
                                                  "test_policy_001",
                                                  "Test Security Check",
                                                  "This is a test security check",
                                                  "Testing rationale for security",
                                                  "Steps to remediate the issue",
                                                  "https://example.com/ref1,https://example.com/ref2",
                                                  "all",
                                                  "PCI_DSS_3.2.1",
                                                  "file:$SSH_CONFIG -> exists",
                                                  "");

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40);
}

TEST_F(SCAChecksumTest, CalculateChecksumFromFields_EmptyStrings_ReturnsNonEmptyString)
{
    std::string checksum = sca::calculateChecksum("", "", "", "", "", "", "", "", "", "", "");

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40);
}

TEST_F(SCAChecksumTest, ConsistentResults_SameDataProducesSameChecksum)
{
    std::string checksum1 = sca::calculateChecksum(sampleCheckData);
    std::string checksum2 = sca::calculateChecksum(sampleCheckData);

    EXPECT_EQ(checksum1, checksum2);
}

TEST_F(SCAChecksumTest, ConsistentResults_JSONAndFieldsProduceSameChecksum)
{
    std::string checksumFromJSON = sca::calculateChecksum(sampleCheckData);

    std::string checksumFromFields = sca::calculateChecksum(sampleCheckData["id"],
                                                            sampleCheckData["policy_id"],
                                                            sampleCheckData["name"],
                                                            sampleCheckData["description"],
                                                            sampleCheckData["rationale"],
                                                            sampleCheckData["remediation"],
                                                            sampleCheckData["refs"],
                                                            sampleCheckData["condition"],
                                                            sampleCheckData["compliance"],
                                                            sampleCheckData["rules"],
                                                            sampleCheckData.value("regex_type", ""));

    EXPECT_EQ(checksumFromJSON, checksumFromFields);
}

TEST_F(SCAChecksumTest, DifferentData_ProducesDifferentChecksums)
{
    nlohmann::json modifiedData = sampleCheckData;
    modifiedData["name"] = "Modified Test Security Check";

    std::string originalChecksum = sca::calculateChecksum(sampleCheckData);
    std::string modifiedChecksum = sca::calculateChecksum(modifiedData);

    EXPECT_NE(originalChecksum, modifiedChecksum);
}

TEST_F(SCAChecksumTest, SensitiveToFieldOrder_DifferentFieldOrderProducesDifferentChecksums)
{
    // Test that changing field values affects the checksum
    std::string checksum1 = sca::calculateChecksum("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "");
    std::string checksum2 = sca::calculateChecksum("b", "a", "c", "d", "e", "f", "g", "h", "i", "j", "");

    EXPECT_NE(checksum1, checksum2);
}

TEST_F(SCAChecksumTest, MissingFields_HandledGracefully)
{
    nlohmann::json partialData =
    {
        {"id", "partial_check"}, {"name", "Partial Check"}, {"description", "Only some fields present"}
        // Missing: policy_id, rationale, remediation, refs, condition, compliance, rules
    };

    std::string checksum = sca::calculateChecksum(partialData);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40);
}

TEST_F(SCAChecksumTest, ValidSHA1Format_ChecksumContainsOnlyHexCharacters)
{
    std::string checksum = sca::calculateChecksum(sampleCheckData);

    // Check that all characters are valid hex digits
    for (char c : checksum)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                << "Invalid hex character found: " << c;
    }
}

TEST_F(SCAChecksumTest, SpecialCharacters_HandledCorrectly)
{
    nlohmann::json specialData = {{"id", "special_check"},
        {"policy_id", "policy:with:colons"},
        {"name", "Check with \"quotes\" and 'apostrophes'"},
        {"description", "Description with\nnewlines\tand\ttabs"},
        {"rationale", "Rationale with special chars: !@#$%^&*()"},
        {"remediation", "Remediation with unicode: αβγδε"},
        {"refs", "ref1;ref2,ref3|ref4"},
        {"condition", "any || all"},
        {"compliance", "PCI_DSS_3.2.1 && NIST_800_53"},
        {"rules", "command[bash] -> 'echo test' contains 'test'"}
    };

    std::string checksum = sca::calculateChecksum(specialData);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40);
}

TEST_F(SCAChecksumIntegrationTest, ChecksumCalculation_ProducesValidResult)
{
    std::string checksum = sca::calculateChecksum(sampleCheck);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40); // SHA1 hex string length

    // Verify it's a valid hex string
    for (char c : checksum)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }
}

TEST_F(SCAChecksumIntegrationTest, ChecksumConsistency_SameDataAlwaysProducesSameChecksum)
{
    std::string checksum1 = sca::calculateChecksum(sampleCheck);
    std::string checksum2 = sca::calculateChecksum(sampleCheck);
    std::string checksum3 = sca::calculateChecksum(sampleCheck);

    EXPECT_EQ(checksum1, checksum2);
    EXPECT_EQ(checksum2, checksum3);
}

TEST_F(SCAChecksumIntegrationTest, ChecksumSensitivity_ModifiedDataProducesDifferentChecksum)
{
    std::string originalChecksum = sca::calculateChecksum(sampleCheck);

    nlohmann::json modifiedCheck = sampleCheck;
    modifiedCheck["name"] = "Modified Integration Test Check";

    std::string modifiedChecksum = sca::calculateChecksum(modifiedCheck);

    EXPECT_NE(originalChecksum, modifiedChecksum);
}

TEST_F(SCAChecksumIntegrationTest, ChecksumWithMissingFields_HandledGracefully)
{
    nlohmann::json minimalCheck = {{"id", "minimal_check"}, {"policy_id", "minimal_policy"}};

    std::string checksum = sca::calculateChecksum(minimalCheck);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 40);
}

// Test that demonstrates the checksum matches between JSON and field-based calculation
TEST_F(SCAChecksumIntegrationTest, ChecksumEquivalence_JSONAndFieldsMatch)
{
    std::string jsonChecksum = sca::calculateChecksum(sampleCheck);

    std::string fieldChecksum = sca::calculateChecksum(sampleCheck.value("id", ""),
                                                       sampleCheck.value("policy_id", ""),
                                                       sampleCheck.value("name", ""),
                                                       sampleCheck.value("description", ""),
                                                       sampleCheck.value("rationale", ""),
                                                       sampleCheck.value("remediation", ""),
                                                       sampleCheck.value("refs", ""),
                                                       sampleCheck.value("condition", ""),
                                                       sampleCheck.value("compliance", ""),
                                                       sampleCheck.value("rules", ""),
                                                       sampleCheck.value("regex_type", ""));

    EXPECT_EQ(jsonChecksum, fieldChecksum);
}
