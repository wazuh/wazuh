#include <stdexcept>
#include <string>
#include <unordered_map>

#include <gtest/gtest.h>

#include <cmcontent/engineTokenStore.hpp>

using namespace cmcontent;

TEST(EngineTokenStoreTest, DelegatesReadsAndWrites)
{
    std::unordered_map<std::string, std::string> state {{"topic-a", "hash-a"}};

    EngineTokenStore store {[&state](std::string_view topic)
                            {
                                const auto it = state.find(std::string {topic});
                                return it == state.end() ? std::string {} : it->second;
                            },
                            [&state](std::string_view topic, std::string_view token)
                            {
                                state[std::string {topic}] = std::string {token};
                                return true;
                            }};

    EXPECT_EQ(store.load("topic-a"), "hash-a");
    EXPECT_EQ(store.load("topic-unknown"), "");

    EXPECT_TRUE(store.store("topic-b", "hash-b"));
    EXPECT_EQ(state.at("topic-b"), "hash-b");
}

TEST(EngineTokenStoreTest, ClearIsAStoreOfTheEmptyHash)
{
    std::string written {"not-written"};

    EngineTokenStore store {[](std::string_view) { return std::string {"hash"}; },
                            [&written](std::string_view, std::string_view token)
                            {
                                written = std::string {token};
                                return true;
                            }};

    // An empty hash is exactly what "nothing committed yet" looks like in both state documents, so
    // clearing needs no separate operation.
    EXPECT_TRUE(store.clear("topic"));
    EXPECT_EQ(written, "");
}

TEST(EngineTokenStoreTest, ReportsAFailedWriteRatherThanThrowing)
{
    EngineTokenStore store {[](std::string_view) { return std::string {}; },
                            [](std::string_view, std::string_view) { return false; }};

    EXPECT_FALSE(store.store("topic", "hash"));
}

TEST(EngineTokenStoreTest, SwallowsCallbackExceptions)
{
    EngineTokenStore store {[](std::string_view) -> std::string { throw std::runtime_error("read blew up"); },
                            [](std::string_view, std::string_view) -> bool { throw std::runtime_error("write blew up"); }};

    // Nothing may cross the DSO boundary: the sink and token-store surface are noexcept, so a
    // failure is reported by value. An unreadable token degrades to "no token", which makes the
    // next cycle a full reload.
    EXPECT_NO_THROW({
        EXPECT_EQ(store.load("topic"), "");
        EXPECT_FALSE(store.store("topic", "hash"));
        EXPECT_FALSE(store.clear("topic"));
    });
}

TEST(EngineTokenStoreTest, MissingCallbacksAreInert)
{
    EngineTokenStore store {nullptr, nullptr};

    EXPECT_EQ(store.load("topic"), "");
    EXPECT_FALSE(store.store("topic", "hash"));
}
