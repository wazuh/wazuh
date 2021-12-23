#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <vector>

#include "registry.hpp"
#include "builder.hpp"


using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

// entry_point as observable
json generate(std::string name, std::string source)
{
    auto t = std::time(nullptr);
    auto tm = *std::gmtime(&t);

    std::string cstr(30, '\0');
    auto len = std::strftime(&cstr[0], cstr.size(), "%FT%TZ%z", &tm);
    cstr.erase(len, std::string::npos);
    return json
    {
        {
            "event", {
                {"original", "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"},
            }
        },
        {
            "wazuh", {
                {
                    "agent", {
                        {"id", "001"},
                        {"name", "agentSim"},
                        {"version", "PoC"},
                    }
                },
                {
                    "event", {
                        {"format", "text"},
                        {"id", "9aa69e7b-e1b0-530e-a710-49108e86019b"},
                        {"ingested", cstr },
                        {"kind", "event"},
                    }
                },
                {
                    "host", {
                        {"architecture", "x86_64"},
                        {"hostname", "hive"},
                        {"ip", "127.0.1.1"},
                        {"mac", "B0:7D:64:11:B3:13"},
                        {
                            "os",
                            {
                                {"kernel", "5.14.14-arch1-1"},
                                {"name", "Linux"},
                                {"type", "posix"},
                                {"version", "#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"},
                            }
                        },
                    }
                },
            }
        },
        {
            "module", {
                {"name", name},
                {"source", source},
            }
        }
    };
}
auto handler = [](subscriber<json> s)
{
    s.on_next(generate("logcollector", "apache-access"));
    s.on_next(generate("logcollector", "apache-error"));
    s.on_next(generate("logcollector", "expected"));
    s.on_next(generate("logcollector", "apache-access"));
    s.on_next(generate("logcollector", "apache-error"));
    s.on_completed();
};
json generate_decoder(const string& name, const string& parent_name, const json& check_stage)
{
    return json
    {
        {"name", name},
        {"parent", parent_name},
        {"check", check_stage}
    };
}

/**************************************************************************************************/
// Check stage tests
/**************************************************************************************************/
TEST(DecoderCheckStageTest, Initializes)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    ASSERT_NO_THROW(auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder.check")));
}

TEST(DecoderCheckStageTest, Builds)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Fake entry poing
    auto entry_point = observable<>::create<json>(handler);

    // Retreive builder
    auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder.check"));

    // Builds
    ASSERT_NO_THROW(auto _observable = _builder->build(entry_point, json::array({ {{"field_1", "+exists"}}, {{"field_2", "value"}}, {{"field_3", 3}} })));

    // Error not json array object
    ASSERT_THROW(auto _observable = _builder->build(entry_point, json({{"field", "value"}})), builder::BuildError);
}

TEST(DecoderCheckStageTest, Operates)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Fake entry poing
    auto entry_point = observable<>::create<json>(handler);

    // Retreive builder
    auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder.check"));

    // Builds
    auto _observable = _builder->build(entry_point, json::array({ {{"wazuh.agent.name", "+exists"}}, {{"module.name", "logcollector"}}, {{"module.source", "expected"}} }));

    // Fake subscriber
    vector<json> observed;
    auto on_next = [&observed](json j)
    {
        observed.push_back(j);
    };
    auto on_complete = []() {};
    auto subscriber = rxcpp::make_subscriber<json>(on_next, on_complete);

    // Operate
    ASSERT_NO_THROW(_observable.subscribe(subscriber));
    ASSERT_EQ(observed.size(), 1);
    for_each(begin(observed), end(observed), [](json j)
    {
        ASSERT_TRUE(j.contains("wazuh"));
        ASSERT_TRUE(j["wazuh"].contains("agent"));
        ASSERT_TRUE(j["wazuh"]["agent"].contains("name"));
        ASSERT_EQ(j["module"]["name"], json("logcollector"));
        ASSERT_EQ(j["module"]["source"], json("expected"));
    });
}

/**************************************************************************************************/
// Decoder tests
/**************************************************************************************************/
TEST(DecoderTest, Initializes)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    ASSERT_NO_THROW(auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder")));
}

TEST(DecoderTest, Builds)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder"));

    // Fake entry poing
    auto entry_point = observable<>::create<json>(handler);

    // Builds
    ASSERT_NO_THROW(auto _observable = _builder->build(entry_point, generate_decoder(
                                                           "decoder_test",
                                                           "none", json::array(
    { {{"field_1", "+exists"}}, {{"field_2", "value"}}, {{"field_3", 3}} }
                                                           ) )));

    // Error not json object
    ASSERT_THROW(auto _observable = _builder->build(entry_point, json::array({ {{"field_1", "+exists"}}, {{"field_2", "value"}}, {{"field_3", 3}} })), builder::BuildError);
}

TEST(DecoderTest, Operates)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder"));

    // Fake entry poing
    auto entry_point = observable<>::create<json>(handler);

    // Builds
    auto _observable = _builder->build(entry_point, generate_decoder(
                                           "decoder_test",
                                           "none", json::array(
    { {{"wazuh.agent.name", "+exists"}}, {{"module.name", "logcollector"}}, {{"module.source", "expected"}} }
                                           ) ));

    // Fake subscriber
    vector<json> observed;
    auto on_next = [&observed](json j)
    {
        observed.push_back(j);
    };
    auto on_complete = []() {};
    auto subscriber = rxcpp::make_subscriber<json>(on_next, on_complete);

    // Operate
    ASSERT_NO_THROW(_observable.subscribe(subscriber));
    ASSERT_EQ(observed.size(), 1);
    for_each(begin(observed), end(observed), [](json j)
    {
        ASSERT_TRUE(j.contains("wazuh"));
        ASSERT_TRUE(j["wazuh"].contains("agent"));
        ASSERT_TRUE(j["wazuh"]["agent"].contains("name"));
        ASSERT_EQ(j["module"]["name"], json("logcollector"));
        ASSERT_EQ(j["module"]["source"], json("expected"));
    });
}
