#ifndef _BUILDER_H
#define _BUILDER_H

#include "_connectable.hpp"
#include "_graph.hpp"
#include "rxcpp/rx.hpp"
#include "json/json.hpp"
#include "builder/outputs/file_output.hpp"
#include <deque>

namespace _builder
{

using Obs_t = rxcpp::observable<json::Document>;
using Sub_t = rxcpp::subscriber<json::Document>;
using Con_t = Connectable<Obs_t>;

using Maker_t = std::function<Con_t(const json::Document &)>;
using Op_t = std::function<Obs_t(const Obs_t &)>;
using Builder_t = std::function<Op_t(const json::Value &)>;
using Graph_t = _graph::Graph<Con_t>;

using namespace builder::internals;

Obs_t unit_op(Obs_t input)
{
    return input;
}

Op_t checkValBuilder(const json::Value & def)
{
    auto valDoc = json::Document(def);
    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() checkValBuilder built" << std::endl;
        return input.filter(
            [valDoc](json::Document e)
            {
                // std::cerr << "op() checkValBuilder executed" << std::endl;
                return e.check(valDoc);
            });
    };
}

Op_t refCheckValBuilder(const std::string path, const std::string ref)
{

    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() checkValBuilder built" << std::endl;
        return input.filter(
            [=](json::Document e)
            {
                // std::cerr << "op() checkValBuilder executed" << std::endl;
                auto v = e.get(ref);
                return e.check(path, v);
            });
    };
}

Op_t mapValBuilder(const json::Value & def)
{
    auto valDoc = json::Document(def);
    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() mapValBuilder built" << std::endl;
        return input.map(
            [valDoc](json::Document e)
            {
                // std::cerr << "op() mapValBuilder executed" << std::endl;
                e.set(valDoc);
                return e;
            });
    };
}

Op_t refMapValBuilder(const std::string path, const std::string ref)
{
    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() refMapValBuilder built" << std::endl;
        return input.map(
            [=](json::Document e)
            {
                auto v = e.get(ref);
                e.set(path, *v);
                // std::cerr << "op() refMapValBuilder executed" << std::endl;
                return e;
            });
    };
}

Op_t checkBuilder(const json::Value & def)
{
    // Check that input is as expected and throw exception otherwise
    if (!def.IsObject())
    {
        throw std::invalid_argument("condition builder expects value to be an object, but got " + def.GetType());
    }

    if (def.GetObject().MemberCount() != 1)
    {
        throw std::invalid_argument("condition build expects value to have only one key, but got" +
                                    def.GetObject().MemberCount());
    }

    auto v = def.MemberBegin();
    if (!v->value.IsString())
        return checkValBuilder(def);

    switch (v->value.GetString()[0])
    {
        case '+':
            throw std::invalid_argument("function helpers not implemented");
            break;
        case '$':
            return refCheckValBuilder(v->name.GetString(), v->value.GetString());
            break;
        default:
            return checkValBuilder(def);
    }
};

Op_t mapBuilder(const json::Value & def)
{
    // Check that input is as expected and throw exception otherwise
    if (!def.IsObject())
    {
        throw std::invalid_argument("map builder expects value to be object, but got " + def.GetType());
    }

    if (def.GetObject().MemberCount() != 1)
    {
        throw std::invalid_argument("map builder expects value to have only one key, but got" +
                                    def.GetObject().MemberCount());
    }

    auto v = def.MemberBegin();
    if (!v->value.IsString())
        return mapValBuilder(def);

    switch (v->value.GetString()[0])
    {
        case '+':
            throw std::invalid_argument("function helpers not implemented");
            break;
        case '$':
            return refMapValBuilder(v->name.GetString(), v->value.GetString());
        default:
            return mapValBuilder(def);
    }
}

Op_t fileOutputBuilder(const json::Value & def)
{
    if (!def.IsObject())
    {
        throw std::invalid_argument("File output builder expects and object, but got " + def.GetType());
    }
    auto obj = def.GetObject();

    if (obj.MemberCount() != 1)
    {
        throw std::invalid_argument("File output builder expects and object with one entry, but got " +
                                    obj.MemberCount());
    }

    auto path = obj.FindMember("path");
    if (path == obj.MemberEnd() || ! path->value.IsString()) {
        throw std::invalid_argument("File output builder expects a .path property defined as a string and pointing to a writable filepath.");
    }

    auto filePtr = std::make_shared<outputs::FileOutput>(path->value.GetString());

    return [=](const Obs_t & input) -> Obs_t {
        input.subscribe([=](auto v) { filePtr->write(v); }, [](){});
        return input;
    };

}

Op_t stageAnyBuilder(const json::Value * def, Builder_t make)
{
    if (!def->IsArray())
    {
        throw std::invalid_argument("Stage chain builder expects definition to be an array, but got " + def->GetType());
    }

    std::vector<Op_t> stagedops;
    for (auto & it : def->GetArray())
    {
        stagedops.push_back(make(it));
    }

    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() stageOrBuilder built" << std::endl;
        std::vector<Obs_t> inputs;
        for (auto op : stagedops)
        {
            inputs.push_back(op(input));
        }
        return rxcpp::observable<>::iterate(inputs).flat_map([](auto o) { return o; });
    };
};

Op_t stageChainBuilder(const json::Value * def, Builder_t make)
{
    if (!def->IsArray())
    {
        throw std::invalid_argument("Stage chain builder expects definition to be an array, but got " + def->GetType());
    }

    std::vector<Op_t> stagedops;
    for (auto & it : def->GetArray())
    {
        stagedops.push_back(make(it));
    }

    return [=](const Obs_t & input) -> Obs_t
    {
        // std::cerr << "op() stageChainBuilder built" << std::endl;
        // this is way better than std::function for 3 reasons: it doesn't
        // require type erasure or memory allocation, it can be constexpr and
        // it works properly with auto (templated) parameters / return type
        auto connect = [=](const Obs_t & in, std::vector<Op_t> remaining, auto & connect_ref) -> Obs_t
        {
            Op_t current = remaining.back();
            remaining.pop_back();
            Obs_t chain = current(in);
            if (remaining.size() == 0)
            {
                return chain;
            }
            return connect_ref(chain, remaining, connect_ref);
        };
        return connect(input, stagedops, connect);
    };
};

Con_t decBuild(const json::Document & def)
{
    const json::Value * name;
    const json::Value * checkVal;
    std::vector<std::string> parents;

    if (def.exists(".parents"))
    {
        for (auto & i : def.get(".parents")->GetArray())
        {
            parents.push_back(i.GetString());
        }
    }

    try
    {
        name = def.get(".name");
    }
    catch (std::invalid_argument e)
    {
        std::throw_with_nested(std::invalid_argument("Decoder builder expects definition to have a .name entry."));
    }

    try
    {
        checkVal = def.get(".check");
    }
    catch (std::invalid_argument e)
    {
        std::throw_with_nested(std::invalid_argument("Decoder builder expects definition to have a .allow section."));
    }

    Op_t checkStage = stageChainBuilder(checkVal, checkBuilder);

    // Normalize stage is optional
    Op_t mapStage = unit_op;
    try
    {
        auto mapVal = def.get(".normalize");
        mapStage = stageChainBuilder(mapVal, mapBuilder);
    }
    catch (std::invalid_argument a)
    {
        // normalize stage is optional, in case of an error do nothign
        // we must ensure nothing else could happen here
    }

    return Con_t(name->GetString(), parents, [=](const Obs_t & input) -> Obs_t { return mapStage(checkStage(input)); });
};

Con_t filterBuild(const json::Document & def)
{

    std::vector<std::string> parents;
    const json::Value * name;
    const json::Value * allow;

    auto after = def.get(".after");
    if (!after || !after->IsArray())
    {
        throw std::invalid_argument("Filter builder expects a filter to have an .after array with the names of the "
                                    "assets this filter will be connected to.");
    }

    for (auto & i : after->GetArray())
    {
        parents.push_back(i.GetString());
    }

    try
    {
        name = def.get(".name");
    }
    catch (std::invalid_argument e)
    {
        std::throw_with_nested(std::invalid_argument("Filter builder expects definition to have a .name entry."));
    }

    try
    {
        allow = def.get(".allow");
    }
    catch (std::invalid_argument e)
    {
        std::throw_with_nested(std::invalid_argument("Filter builder expects definition to have a .allow section."));
    }

    Op_t checkStage = stageChainBuilder(allow, checkBuilder);

    return Con_t(name->GetString(), parents, [=](const Obs_t & input) -> Obs_t { return checkStage(input); });
};

Op_t outputsStageBuilder(const json::Value * def)
{

    if (!def->IsArray())
    {
        throw std::invalid_argument("Output stage builder expects outputs section to be an array, but got " +
                                    def->GetType());
    }

    std::vector<Op_t> stagedops;

    for (auto & o : def->GetArray())
    {
        if (!o.IsObject())
        {
            throw std::invalid_argument(
                "Output stage builder expets .outputs array to be composed of objects, but got " + o.GetType());
        }
        std::string stage = o.MemberBegin()->name.GetString();

        if (stage != "file")
        {
            throw std::invalid_argument("Output stage builder got an unknown output definition in .outputs section "+stage);
        }
        
        stagedops.push_back(fileOutputBuilder(o.MemberBegin()->value));
    }

    return [=](Obs_t input) -> Obs_t
    {
        std::cerr << "op() outputsStageBuilder built" << std::endl;
        std::vector<Obs_t> inputs;
        for (auto op : stagedops)
        {
            inputs.push_back(op(input));
        }
        return rxcpp::observable<>::iterate(inputs).flat_map([](auto o) { return o; });
    };
}

Con_t outputBuild(const json::Document & def)
{
    std::vector<std::string> parents;
    const json::Value * name;
    const json::Value * checkVal;
    const json::Value * outputs;

    if (def.exists(".parents"))
    {
        for (auto & i : def.get(".parents")->GetArray())
        {
            parents.push_back(i.GetString());
        }
    }

    try
    {
        name = def.get(".name");
    }
    catch (std::invalid_argument e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .name entry."));
    }

    try
    {
        checkVal = def.get(".check");
    }
    catch (std::invalid_argument e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .allow section."));
    }

    Op_t checkStage = stageChainBuilder(checkVal, checkBuilder);

    try
    {
        outputs = def.get(".outputs");
    }
    catch (std::invalid_argument e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .outputs section."));
    }
    Op_t outputsStage = outputsStageBuilder(outputs);
    
    return Con_t(name->GetString(), parents,[=](const Obs_t & input) -> Obs_t { return outputsStage(checkStage(input)); });
}

template <class Catalog>
void assetBuilder(Catalog c, Graph_t & g, std::string atype, const json::Value * v, Maker_t make)
{

    if (v && v->IsArray())
    {
        for (auto & m : v->GetArray())
        {
            json::Document asset = c.getAsset(atype, m.GetString());
            g.node(make(asset));
        }
    }
}

void connectGraph(Graph_t & g, Con_t in, Con_t out)
{

    g.node(in);

    g.visit(
        [&](auto edges)
        {
            Con_t node = edges.first;
            // TODO: do not relay on special names with input and output in the name
            if (node == in || node == out || node.name.find("input") != std::string::npos ||
                node.name.find("output") != std::string::npos)
                return;

            if (node.parents.size() == 0 && edges.second.size() == 0)
            {
                g.add_edge(in, node);
            }

            for (auto p : node.parents)
            {
                g.add_edge(Con_t(p), node);
            }
        });

    g.node(out);

    g.leaves(
        [&](Con_t leaf)
        {
            if (leaf != out)
            {
                g.add_edge(leaf, out);
            }
        });
}

void filterGraph(Graph_t & g, Con_t root, Graph_t & filters)
{
    filters.visit(
        [&](auto edges)
        {
            Con_t filter = edges.first;
            for (auto & p : filter.parents)
            {
                g.node(filter);
                g.inject(Con_t(p), filter);
            }
        });
}

template <class Catalog> Graph_t environmentBuilder(Catalog c, std::string name)
{
    Graph_t g;
    Graph_t filters;
    json::Document asset = c.getAsset("environment", name);

    assetBuilder<Catalog>(c, g, "decoder", asset.get(".decoders"), decBuild);
    connectGraph(g, Con_t("decoders_input"), Con_t("decoders_output"));

    g.node(Con_t("rules_input"));
    g.add_edge(Con_t("decoders_output"), Con_t("rules_input"));

    assetBuilder<Catalog>(c, g, "rule", asset.get(".rules"), decBuild);
    connectGraph(g, Con_t("rules_input"), Con_t("rules_output"));

    g.node(Con_t("outputs_input"));
    g.add_edge(Con_t("decoders_output"), Con_t("outputs_input"));
    g.add_edge(Con_t("rules_output"), Con_t("outputs_input"));

    assetBuilder<Catalog>(c, g, "output", asset.get(".outputs"), outputBuild);
    connectGraph(g, Con_t("outputs_input"), Con_t("outputs_output"));

    assetBuilder<Catalog>(c, filters, "filter", asset.get(".filters"), filterBuild);
    filterGraph(g, Con_t("decoders_input"), filters);

    return g;
}


} // namespace _builder
#endif
