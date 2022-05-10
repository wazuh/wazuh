#include "testUtils.hpp"

#include "_builder/registry.hpp"

TEST(Registry, RegisterBuilder)
{
    // ASSERT_NO_THROW(RegisterBuilder("test", [](int) { return nullptr; }));
    // EXPECT_THROW(RegisterBuilder("test", [](int) { return nullptr; }),
    //              std::runtime_error);
    // auto instance = _Registry<
    //     std::function<std::shared_ptr<IConnectable>(void)>>::getInstance();
    // RegisterBuilder("test", [](int) { return nullptr; });
    // RegisterBuilder("test", [](int) { return nullptr; });
    // RegisterBuilder("test", [](int) { return nullptr; });
    // GTEST_COUT << instance.m_builders.size();
}
