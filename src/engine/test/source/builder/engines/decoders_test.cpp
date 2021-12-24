#include <gtest/gtest.h>
#include <string>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

#include "builder.hpp"
#include "registry.hpp"

#define GTEST_COUT std::cout << "[          ] [ INFO ] "


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
    s.on_next(generate("logcollector", "expected_1"));
    s.on_next(generate("logcollector", "expected_5"));
    s.on_next(generate("logcollector", "expected_3"));
    s.on_next(generate("logcollector", "expected_2"));
    s.on_next(generate("logcollector", "expected_0"));
    s.on_next(generate("logcollector", "expected_4"));
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

TEST(DecodersTest, Initializes)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    ASSERT_NO_THROW(auto _builder = static_cast<const builder::MultiJsonBuilder*>(registry.get_builder("decoders")));
}

TEST(DecodersTest, Builds)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    auto _builder = static_cast<const builder::MultiJsonBuilder*>(registry.get_builder("decoders"));

    // Fake entry poing
    auto entry_point = observable<>::create<json>(handler);

    // Input decoders
    vector<json> decoders;

    for (auto i = 0; i < 3; i++)
    {
        decoders.push_back(generate_decoder(
                               "decoder_test",
                               "none", json::array(
        { {{"field_1", "+exists"}}, {{"field_2", "value"}}, {{"field_3", "expected_" + to_string(i)}} }
                               ) ));
    }

    // Build
    ASSERT_NO_THROW(auto _observable = _builder->build(entry_point, decoders));
}

TEST(DecodersTest, Operates)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    auto _builder = static_cast<const builder::MultiJsonBuilder*>(registry.get_builder("decoders"));

    // Fake entry poing
    observable<json> entry_point = observable<>::create<json>(handler);

    // Fake subscriber
    vector<json> observed;
    auto on_next = [&observed](json j)
    {
        observed.push_back(j);
    };
    auto on_complete = []() {};
    auto subscriber = rxcpp::make_subscriber<json>(on_next, on_complete);



    // Input decoders
    vector<json> decoders;

    for (auto i = 0; i < 3; i++)
    {
        decoders.push_back(generate_decoder(
                               "decoder_test",
                               "none", json::array(
        { {{"module.name", "+exists"}}, {{"module.source", string("expected_" + to_string(i))}} }
                               ) ));
    }

    // Build
    auto _observable = _builder->build(entry_point, decoders);

    // Assuming decoders are built
    vector<observable<json>> decoders_obs;

    for (auto dec : decoders)
    {
        decoders_obs.push_back(static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder"))->build(entry_point, dec));
    }



    //decoders_obs[2].concat_map(decoders_obs[0]).subscribe(subscriber);
    // observable<json> incognito_0 = entry_point.concat_map(
    //     // Collection selector
    //     [&decoders_obs](json j){
    //         return observable<>::just<json>(j).concat(decoders_obs[0]);
    //     },
    //     // Result selector
    //     [](json in, json out){
    //         return out;
    //     }
    // );
    // observable<json> incognito_1 = entry_point.concat_map(
    //     // Collection selector
    //     [&decoders_obs](json j){
    //         return observable<>::start_with(decoders_obs[1], j);
    //     },
    //     // Result selector
    //     [](json in, json out){
    //         return out;
    //     }
    // );


    decoders_obs[0].concat(decoders_obs[1]).subscribe(subscriber);
    //observable<>::from(decoders_obs[0], decoders_obs[1]).merge().subscribe(subscriber);
    //incognito_0.merge(incognito_1).subscribe(subscriber);
    // auto incognito = entry_point.on_error_resume_next();
    //incognito_0.subscribe(subscriber);
    for_each(begin(observed), end(observed), [](json j)
    {
        GTEST_COUT << j["module"]["source"] << endl;
    });

}
