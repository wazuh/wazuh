#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <algorithm>
#include <vector>
#include <map>
#include <string>

#include "builder.hpp"
#include "registry.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "


using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

// Fake engine class
class FakeEngine
{
    public:
        FakeEngine(const string& engine_id, const vector<json>& resources): engine_id(engine_id), resources(resources) {}
        vector<json> resources;
        string engine_id;
};

// Fake catalog class
typedef vector<FakeEngine> FakeConf;
class FakeCatalog
{
    public:
        map<string, FakeConf> catalog;
        void add_enviroment(const string& enviroment_id, const vector<FakeEngine>& engines)
        {
            this->catalog[enviroment_id] = engines;
        }
        FakeConf get_conf(const string& enviroment_id)
        {
            return this->catalog[enviroment_id];
        }
};

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
    s.on_next(generate("logcollector", "apache-access"));
    s.on_next(generate("logcollector", "apache-error"));
    s.on_completed();
};

// Dummy builders
namespace
{
    observable<json> decoder_build(const observable<json>& obs, const vector<json>& decoders)
    {
        GTEST_COUT << "Decoder engine builder called" << endl;
        return obs;
    }
    builder::MultiJsonBuilder decoder_builder("decoder_engine", &decoder_build);
}



// Acceptance test
// Builder returns proper enviroment object when a configuration is given to it
TEST(BuilderTest, BuilderBuilds)
{
    // Assumption registry is build and populated
    builder::Registry& registry = builder::Registry::instance();
    GTEST_COUT << "Registry instance retreived" << endl;
    // Set up FakeCatalog
    vector<json> decoders;

    for (int i = 0; i < 10; i++)
    {
        decoders.push_back(json(
        {
            "name",
            string("decoder_").append(to_string(i))
        }));
    }

    FakeCatalog catalog;
    FakeEngine decoder_engine("decoder_engine", decoders);
    vector<FakeEngine> engines;
    engines.push_back(decoder_engine);
    catalog.add_enviroment("enviroment_test", engines);

    // An enviroment id is passed to the builder
    string enviroment_id = "enviroment_test";

    // We request the configuration to the catalog
    FakeConf conf = catalog.get_conf(enviroment_id);
    GTEST_COUT << "Configuration retreived" << endl;

    // Build observable entry point, where subsequents observable operations are concatenated
    observable<json> entry_point = observable<>::create<json>(handler);
    GTEST_COUT << "Entry point built" << endl;


    // and iterate over each engine, building the appropiate object.
    // When building the object an observable is passed, operations are applied to
    // the observable, returning the combined observable
    observable<json> current_point = entry_point;
    for_each(begin(conf), end(conf), [&registry, &current_point](FakeEngine e)
    {
        GTEST_COUT << "Start building " << e.engine_id << endl;
        const builder::MultiJsonBuilder* eng_ptr = (const builder::MultiJsonBuilder*)(registry.get_builder(e.engine_id));
        GTEST_COUT << "Decoder engine builder retreived" << endl;
        current_point = eng_ptr->build(current_point, e.resources);
    });
    GTEST_COUT << "Enviroment built" << endl;
    // current_point holds now all operations combined
}
