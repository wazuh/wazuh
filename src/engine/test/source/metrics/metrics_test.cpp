#include "metrics.hpp"
#include <gtest/gtest.h>
#include <filesystem>

const auto INPUT_PATH {(std::filesystem::current_path() / "source/metrics/input_files/context.json").string()};

class MetricsTest : public ::testing::Test
{
protected:
    std::shared_ptr<Metrics> m_spMetrics;
    MetricsTest() = default;
    ~MetricsTest() override = default;
    void SetUp() override
    {
        m_spMetrics = std::make_shared<Metrics>();
        m_spMetrics->initMetrics("test", INPUT_PATH);
    }
};

TEST_F(MetricsTest, invalidValueCounter)
{
    EXPECT_ANY_THROW(m_spMetrics->addCounterValue("Sockets", -1));
}

TEST_F(MetricsTest, nameCounterNotDefined)
{
    EXPECT_ANY_THROW(m_spMetrics->addCounterValue("RandomName", 1));
}

TEST_F(MetricsTest, sucessCounter)
{
    for (auto i = 0; i < 10; i ++)
    {
        m_spMetrics->addCounterValue("Sockets", 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        m_spMetrics->addCounterValue("Request", 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}
