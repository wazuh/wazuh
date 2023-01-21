
#include <router/runtimeEnvironment.hpp>

#include <string>

#include <gtest/gtest.h>

#include "testAuxiliar/routerAuxiliarFunctions.hpp"

#include "parseEvent.hpp"
#include "register.hpp"

constexpr auto env_1 = "environment/env_1/0";
constexpr auto env_2 = "environment/env_2/0";
constexpr auto env_default = "environment/default/0";


TEST(RuntimeEnvironment, build_ok)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto error = environment->build(builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
}

TEST(RuntimeEnvironment, build_fail_env)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>("invalid_env");
    auto error = environment->build(builder);
    ASSERT_TRUE(error.has_value());
}

TEST(RuntimeEnvironment, build_fail_builder)
{
    GTEST_SKIP();
    auto environment = std::make_shared<router::RuntimeEnvironment>("invalid_env");
    // TODO SHOULD BE ASSERT_THROW LOGIC ERROR
    environment->build(nullptr);
}

TEST(RuntimeEnvironment, build_2_times)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto error = environment->build(builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
    error = environment->build(builder);
    ASSERT_TRUE(error.has_value());
    ASSERT_STREQ(error.value().message.c_str(), "Environment 'environment/env_1/0' is already built.");
}

TEST(RuntimeEnvironment, processEvent_not_built)
{
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto e = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[0]);
    auto error = environment->processEvent(e);
    ASSERT_TRUE(error.has_value());
    ASSERT_STREQ(error.value().message.c_str(), "Environment 'environment/env_1/0' is not built.");
}


TEST(RuntimeEnvironment, processEvent_1_event)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto error = environment->build(builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    auto e = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[0]);

    // Send event
    auto decoderPath = json::Json::formatJsonPath("~decoder");
    auto result = environment->processEvent(e);
    ASSERT_FALSE(result) << result.value().message;
    ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
    ASSERT_EQ(e->getString(decoderPath).value(), "deco_1") << e->prettyStr();
}

// TODO add more tests
TEST(RuntimeEnvironment, processEvent_30_event)
{
    auto builder = aux::getFakeBuilder();
    auto environment = std::make_shared<router::RuntimeEnvironment>(env_1);
    auto error = environment->build(builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
    auto decoderPath = json::Json::formatJsonPath("~decoder");

    for (std::size_t i = 0; i < 30; i += 3)
    {
        auto e = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[i % 3]);
        // Send event
        auto result = environment->processEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_1") << e->prettyStr();

        e = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[(i + 1) % 3]);
        // Send event
        result = environment->processEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_2") << e->prettyStr();

        e = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[(i + 2) % 3]);
        // Send event
        result = environment->processEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_3") << e->prettyStr();
    }
}
