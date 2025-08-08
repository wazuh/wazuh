#include <sca_checksum.hpp>
#include <sca_policy_loader.hpp>

#include <gtest/gtest.h>
#include <json.hpp>

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
                       {"rules", "file:/etc/test -> exists"}};
    }

    nlohmann::json sampleCheck;
};

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
                                                       sampleCheck.value("rules", ""));

    EXPECT_EQ(jsonChecksum, fieldChecksum);
}
