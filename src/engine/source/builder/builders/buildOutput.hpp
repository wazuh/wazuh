#ifndef _BUILDERS_INTERNAL_OUTPUT_H
#define _BUILDERS_INTERNAL_OUTPUT_H

#include <stdexcept>
#include <vector>

#include "connectable.hpp"
#include "json.hpp"
#include "outputs/file.hpp"
#include "rxcpp/rx.hpp"

namespace builder::internals::builders
{

// The type of the event which will flow through the stream
using Event_t = json::Document;
// The type of the observable which will compose the processing graph
using Obs_t = rxcpp::observable<Event_t>;
// The type of a connectable operation
using Op_t = std::function<Obs_t(const Obs_t &)>;

Op_t buildFileOutput(const json::Value & def)
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
    if (path == obj.MemberEnd() || !path->value.IsString())
    {
        throw std::invalid_argument(
            "File output builder expects a .path property defined as a string and pointing to a writable filepath.");
    }

    std::string filepath = path->value.GetString();

    return [=](const Obs_t & input) -> Obs_t
    {
        auto filePtr = std::make_shared<builder::internals::outputs::FileOutput>(filepath);
        input.subscribe([=](auto v) { filePtr->write(v); },
                        [](std::exception_ptr e){
                            std::cerr << rxcpp::util::what(e).c_str() << std::endl;
                        },
                        [=]() { // filePtr->close(); 
                        });
        return input;
    };
}

Op_t buildOutputStage(const json::Value * def)
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
            throw std::invalid_argument("Output stage builder got an unknown output definition in .outputs section " +
                                        stage);
        }

        stagedops.push_back(buildFileOutput(o.MemberBegin()->value));
    }

    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() buildOutputStage built" << std::endl;
        std::vector<Obs_t> inputs;
        for (auto op : stagedops)
        {
            inputs.push_back(op(input));
        }
        return rxcpp::observable<>::iterate(inputs).flat_map([](auto o) { return o; });
    };
}

} // namespace builder::internals::builders

#endif // _BUILDERS_INTERNAL_OUTPUT_H
