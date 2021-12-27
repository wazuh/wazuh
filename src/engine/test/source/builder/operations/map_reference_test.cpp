#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <algorithm>
#include <vector>

#include "builder.hpp"
#include "registry.hpp"

#define GTEST_COUT std::cout << "[          ] [ INFO ] "


using json = nlohmann::json;
using namespace std;

// entry_point as observable
json generate()
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
                {"name", "logtest"},
                {"source", "apache"},
                {"field_value", "changed"},
                {"map_field", "unchanged"},
            }
        }
    };
}
json generate_with_missing_field()
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
                {"name", "logtest"},
                {"source", "apache"},
                {"field_value", "changed"},
            }
        }
    };
}

auto handler = [](rxcpp::subscriber<json> s)
{
    s.on_next(generate());
    s.on_next(generate_with_missing_field());
    s.on_completed();
};

TEST(MapReferenceTest, Initializes)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    ASSERT_NO_THROW(auto builder = registry.get_builder("map.reference"));
}

TEST(MapReferenceTest, Builds)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Fake entry poing
    auto entry_point = rxcpp::observable<>::create<json>(handler);

    // Retreive builder
    auto _builder = (const builder::JsonBuilder*)(registry.get_builder("map.reference"));

    // Build
    ASSERT_NO_THROW(auto _observable = _builder->build(entry_point, json({{"field", "value"}})));

    // Error not json object
    ASSERT_THROW(auto _observable = _builder->build(entry_point, json({"field", "value"})), builder::BuildError);

    // Error more than one key
    ASSERT_THROW(auto _observable = _builder->build(entry_point, json({{"field", "value"}, {"error", "value"}})), builder::BuildError);
}

TEST(MapReferenceTest, Operates)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Fake entry poing
    rxcpp::observable<json> entry_point = rxcpp::observable<>::create<json>(handler);

    // Retreive builder
    auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("map.reference"));

    // Build
    auto _observable = _builder->build(entry_point, json({{"module.map_field", "module.field_value"}}));

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
    ASSERT_EQ(observed.size(), 2);
    for_each(begin(observed), end(observed), [](json j)
    {
        ASSERT_EQ(j["module"]["map_field"], json("changed"));
    });
}
