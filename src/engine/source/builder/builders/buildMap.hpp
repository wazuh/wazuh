#ifndef _BUILDERS_MAP_H
#define _BUILDERS_MAP_H

#include <stdexcept>
#include <string>
#include <vector>

#include "json.hpp"
#include "rxcpp/rx.hpp"
#include "syntax.hpp"

namespace builder::internals::builders
{

// The type of the event which will flow through the stream
using Event_t = json::Document;
// The type of the observable which will compose the processing graph
using Obs_t = rxcpp::observable<Event_t>;
// The type of a connectable operation
using Op_t = std::function<Obs_t(const Obs_t &)>;

Op_t buildMapVal(const json::Value & def)
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

Op_t buildMapRef(const std::string path, const std::string ref)
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

/**
 * @brief convers an map-type definition into an operation
 * which will execute all the transofmations defined.
 *
 * @param def definition of the map stage
 * @return Op_t
 */
Op_t buildMap(const json::Value & def)
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
        return buildMapVal(def);

    switch (v->value.GetString()[0])
    {
        case builder::internals::syntax::FUNCTION_HELPER_ANCHOR:
            throw std::invalid_argument("function helpers not implemented");
            break;
        case builder::internals::syntax::REFERENCE_ANCHOR:
            return buildMapRef(v->name.GetString(), v->value.GetString());
        default:
            return buildMapVal(def);
    }
}

} // namespace builder::internals::builders

#endif // _BUILDERS_MAP_H
