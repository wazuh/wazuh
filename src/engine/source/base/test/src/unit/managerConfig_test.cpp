#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <unistd.h>

#include <base/managerConfig.hpp>

namespace fs = std::filesystem;

namespace
{
const std::string VALID_XML = "  <cluster>\n"
                              "    <name>wazuh-xml</name>\n"
                              "    <node_name>node07</node_name>\n"
                              "    <key>0123456789abcdef0123456789abcdef</key>\n"
                              "  </cluster>\n"
                              "  <indexer>\n"
                              "    <hosts>\n"
                              "      <host>https://10.0.0.1:9200</host>\n"
                              "    </hosts>\n"
                              "    <ssl>\n"
                              "      <certificate>etc/certs/indexer.pem</certificate>\n"
                              "      <key>etc/certs/indexer-key.pem</key>\n"
                              "    </ssl>\n"
                              "  </indexer>\n";

class ManagerConfigTest : public ::testing::Test
{
protected:
    fs::path m_home;

    void SetUp() override
    {
        m_home = fs::temp_directory_path() / ("base_managerConfig_test_" + std::to_string(::getpid()));
        fs::remove_all(m_home);
        fs::create_directories(m_home / "etc");
        base::managerConfig::reset();
    }

    void TearDown() override
    {
        base::managerConfig::reset();
        fs::remove_all(m_home);
    }

    void writeConfig(const std::string& body) const
    {
        std::ofstream file(m_home / "etc" / "wazuh-manager.conf");
        file << "<wazuh_config>\n" << body << "</wazuh_config>\n";
    }
};
} // namespace

TEST_F(ManagerConfigTest, NotLoadedIsEmpty)
{
    EXPECT_FALSE(base::managerConfig::isLoaded());
    EXPECT_TRUE(base::managerConfig::sectionJson("indexer").empty());

    const auto [clusterName, nodeName] = base::managerConfig::clusterNames();
    EXPECT_TRUE(clusterName.empty());
    EXPECT_TRUE(nodeName.empty());
}

TEST_F(ManagerConfigTest, LoadsSectionsFromHome)
{
    writeConfig(VALID_XML);

    // The certificate files do not exist: a normal start does not require them (only -t does).
    ASSERT_NO_THROW(base::managerConfig::load(m_home));
    EXPECT_TRUE(base::managerConfig::isLoaded());

    const auto indexer = base::managerConfig::sectionJson("indexer");
    EXPECT_NE(indexer.find("\"hosts\":[\"https://10.0.0.1:9200\"]"), std::string::npos) << indexer;
    EXPECT_NE(indexer.find("\"certificate\":\"etc/certs/indexer.pem\""), std::string::npos) << indexer;

    const auto [clusterName, nodeName] = base::managerConfig::clusterNames();
    EXPECT_EQ(clusterName, "wazuh-xml");
    EXPECT_EQ(nodeName, "node07");

    // Sections the schema defines are always present (defaults applied); unknown ones are not.
    EXPECT_NE(base::managerConfig::sectionJson("logging").find("\"log_format\""), std::string::npos);
    EXPECT_TRUE(base::managerConfig::sectionJson("no-such-section").empty());
}

TEST_F(ManagerConfigTest, ValidateReportsPointer)
{
    writeConfig(VALID_XML + "  <vulnerability-detection>\n    <pageSize>0</pageSize>\n  </vulnerability-detection>\n");

    auto error = base::managerConfig::validate(m_home);
    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error->rfind("/vulnerability-detection/pageSize", 0), 0u) << *error;

    // Valid document, but -t also requires the referenced certificate files to exist (the first one
    // checked is the remoted HTTPS certificate the schema defaults fill in).
    writeConfig(VALID_XML);
    error = base::managerConfig::validate(m_home);
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->find("file not found"), std::string::npos) << *error;
    EXPECT_EQ(error->rfind("/remote/https/certificate", 0), 0u) << *error;

    // load() succeeds on the same document and validate() does not touch what is loaded.
    ASSERT_NO_THROW(base::managerConfig::load(m_home));
    EXPECT_TRUE(base::managerConfig::isLoaded());
}

TEST_F(ManagerConfigTest, LoadMissingFileThrows)
{
    EXPECT_THROW(base::managerConfig::load(m_home), std::runtime_error);
    EXPECT_FALSE(base::managerConfig::isLoaded());

    const auto error = base::managerConfig::validate(m_home);
    ASSERT_TRUE(error.has_value());
}
