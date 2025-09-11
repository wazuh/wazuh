#include <gtest/gtest.h>

#include <base/logging.hpp>

#include <metrics/manager.hpp>

class Environment : public ::testing::Environment
{
public:
    ~Environment() override = default;

    void SetUp() override
    {
        logging::testInit(logging::Level::Off);
        // Initialize/destroy the Manager so shared global state defined by OT is created for every test
        {
            metrics::Manager manager;
        }
    }
};

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    testing::AddGlobalTestEnvironment(new Environment);
    return RUN_ALL_TESTS();
}
