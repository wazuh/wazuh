
#include <router/runtimeEnvironment.hpp>

#include <string>

#include <gtest/gtest.h>

#include "testAuxiliar/routerAuxiliarFunctions.hpp"

#include "parseEvent.hpp"
#include "register.hpp"

constexpr auto env_1 = "environment/env_1/0";
constexpr auto env_2 = "environment/env_2/0";
constexpr auto env_default = "environment/default/0";

namespace
{
// Make event
// std::list<base::Event> events {};
// std::transform(sampleEventsStr.begin(), sampleEventsStr.end(), std::back_inserter(events), [](const auto& str) {
//     return  base::parseEvent::parseOssecEvent(str);
// });
const std::vector<std::string> sampleEventsStr {
    R"(2:10.0.0.1:Test Event - deco_1 )",
    R"(4:10.0.0.1:Test Event - deco_2 )",
    R"(8:10.0.0.1:Test Event - deco_3 )"
    };

} // namespace

TEST(RuntimeEnvironment, build_ok)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto error = environment->build(builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
}

// TODO add more failure tests
TEST(RuntimeEnvironment, build_fail)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>("invalid_env");
    auto error = environment->build(builder);
    ASSERT_TRUE(error.has_value());
}

// TODO add more tests
TEST(RuntimeEnvironment, push_1_event)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto error = environment->build(builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    auto e = base::parseEvent::parseOssecEvent(sampleEventsStr[0]);

    // Send event
    auto decoderPath = json::Json::formatJsonPath("~decoder");
    auto result = environment->pushEvent(e);
    ASSERT_FALSE(result) << result.value().message;
    ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
    ASSERT_EQ(e->getString(decoderPath).value(), "deco_1") << e->prettyStr();
}

// TODO add more tests
TEST(RuntimeEnvironment, push_30_event)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto error = environment->build(builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
    auto decoderPath = json::Json::formatJsonPath("~decoder");

    for (std::size_t i = 0; i < 30; i += 3)
    {
        auto e = base::parseEvent::parseOssecEvent(sampleEventsStr[i % 3]);
        // Send event
        auto result = environment->pushEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_1") << e->prettyStr();

        e = base::parseEvent::parseOssecEvent(sampleEventsStr[(i + 1) % 3]);
        // Send event
        result = environment->pushEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_2") << e->prettyStr();

        e = base::parseEvent::parseOssecEvent(sampleEventsStr[(i + 2) % 3]);
        // Send event
        result = environment->pushEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_3") << e->prettyStr();
    }
}

// TODO add more tests
TEST(RuntimeEnvironment, mutiple_environments)
{
    std::size_t numEnvironments = 20;
    std::size_t numEvents = 500;
    const auto decoderPath = json::Json::formatJsonPath("~decoder");
    auto builder = aux::getFakeBuilder();

    std::vector<std::shared_ptr<router::RuntimeEnvironment>> environments {};

    for (std::size_t i = 0; i < numEnvironments; i++)
    {
        auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
        auto error = environment->build(builder);
        ASSERT_FALSE(error.has_value()) << error.value().message;
        environments.push_back(environment);
    }

    for (std::size_t i = 0; i < numEvents; i++)
    {
        base::Event e;
        ASSERT_NO_THROW(e = base::parseEvent::parseOssecEvent(sampleEventsStr[0]));

        // Send event
        auto result = environments[i % numEnvironments]->pushEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_1") << e->prettyStr();


    }
}
