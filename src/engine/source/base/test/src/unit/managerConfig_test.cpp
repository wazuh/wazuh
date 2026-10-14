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
    // The real file lives in the fixed /etc/wazuh-manager: tests pass their own to load()/validate().
    fs::path m_file;

    void SetUp() override
    {
        m_home = fs::temp_directory_path() / ("base_managerConfig_test_" + std::to_string(::getpid()));
        m_file = m_home / "wazuh-manager.conf";
        fs::remove_all(m_home);
        fs::create_directories(m_home);
        base::managerConfig::reset();
    }

    void TearDown() override
    {
        base::managerConfig::reset();
        fs::remove_all(m_home);
    }

    void writeConfig(const std::string& body) const
    {
        std::ofstream file(m_file);
        file << "<wazuh_config>\n" << body << "</wazuh_config>\n";
    }
};
} // namespace

TEST_F(ManagerConfigTest, DefaultFileIsInTheFixedConfigurationDirectory)
{
    EXPECT_EQ(base::managerConfig::filePath(), fs::path("/etc/wazuh-manager/wazuh-manager.conf"));
}

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
    ASSERT_NO_THROW(base::managerConfig::load(m_home, m_file));
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

    auto error = base::managerConfig::validate(m_home, m_file);
    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error->rfind("/vulnerability-detection/pageSize", 0), 0u) << *error;

    // Valid document, but -t also requires the referenced certificate files to exist (the first one
    // checked is the remoted HTTPS certificate). Named relative here, so it resolves against the home
    // instead of the build host's real /etc/wazuh-manager/certs the schema default points at.
    writeConfig(VALID_XML
                + "  <remote>\n    <https>\n      <certificate>etc/certs/remoted.pem</certificate>\n"
                  "      <key>etc/certs/remoted-key.pem</key>\n    </https>\n  </remote>\n");
    error = base::managerConfig::validate(m_home, m_file);
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->find("file not found"), std::string::npos) << *error;
    EXPECT_NE(error->find((m_home / "etc/certs/remoted.pem").string()), std::string::npos) << *error;
    EXPECT_EQ(error->rfind("/remote/https/certificate", 0), 0u) << *error;

    // load() succeeds on the same document and validate() does not touch what is loaded.
    ASSERT_NO_THROW(base::managerConfig::load(m_home, m_file));
    EXPECT_TRUE(base::managerConfig::isLoaded());
}

TEST_F(ManagerConfigTest, LoadMissingFileThrows)
{
    EXPECT_THROW(base::managerConfig::load(m_home, m_file), std::runtime_error);
    EXPECT_FALSE(base::managerConfig::isLoaded());

    const auto error = base::managerConfig::validate(m_home, m_file);
    ASSERT_TRUE(error.has_value());
}

TEST_F(ManagerConfigTest, LogFormatDefault)
{
    // No <logging> section: the schema default ["plain"] applies
    writeConfig(VALID_XML);
    ASSERT_NO_THROW(base::managerConfig::load(m_home, m_file));

    const auto format = base::managerConfig::logFormat();
    EXPECT_TRUE(format.plain);
    EXPECT_FALSE(format.json);
}

TEST_F(ManagerConfigTest, LogFormatJsonOnly)
{
    writeConfig(VALID_XML + "  <logging>\n    <log_format>json</log_format>\n  </logging>\n");
    ASSERT_NO_THROW(base::managerConfig::load(m_home, m_file));

    const auto format = base::managerConfig::logFormat();
    EXPECT_FALSE(format.plain);
    EXPECT_TRUE(format.json);
}

TEST_F(ManagerConfigTest, LogFormatBoth)
{
    writeConfig(VALID_XML + "  <logging>\n    <log_format>json,plain</log_format>\n  </logging>\n");
    ASSERT_NO_THROW(base::managerConfig::load(m_home, m_file));

    const auto format = base::managerConfig::logFormat();
    EXPECT_TRUE(format.plain);
    EXPECT_TRUE(format.json);
}

TEST_F(ManagerConfigTest, LogFormatInvalid)
{
    // The schema only accepts plain/json: an unknown format makes load() fail, and without a document the
    // default {plain} is answered.
    writeConfig(VALID_XML + "  <logging>\n    <log_format>syslog</log_format>\n  </logging>\n");
    EXPECT_THROW(base::managerConfig::load(m_home, m_file), std::runtime_error);

    const auto format = base::managerConfig::logFormat();
    EXPECT_TRUE(format.plain);
    EXPECT_FALSE(format.json);
}

TEST_F(ManagerConfigTest, LogFormatNoSection)
{
    // Nothing loaded (standalone mode): no document, no section
    ASSERT_FALSE(base::managerConfig::isLoaded());

    const auto format = base::managerConfig::logFormat();
    EXPECT_TRUE(format.plain);
    EXPECT_FALSE(format.json);
}
