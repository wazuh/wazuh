#ifndef _BUILDERS_CHECK_H
#define _BUILDERS_CHECK_H

#include <stdexcept>
#include <string>
#include <vector>

#include "json.hpp"
#include "rxcpp/rx.hpp"
#include "syntax.hpp"

namespace builder::internals::builders
{
using namespace builder::internals::syntax;

// The type of the event which will flow through the stream
using Event_t = json::Document;
// The type of the observable which will compose the processing graph
using Obs_t = rxcpp::observable<Event_t>;
// The type of a connectable operation
using Op_t = std::function<Obs_t(const Obs_t &)>;

Obs_t unit_op(Obs_t input)
{
    return input;
}

Op_t buildCheckVal(const json::Value & def)
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

Op_t buildCheckFH(const std::string path)
{

    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() checkValBuilder built" << std::endl;
        return input.filter(
            [=](json::Document e)
            {
                // auto v = e.get(ref);
                return e.exists("/"+path);
            });
    };
}

Op_t buildCheckRef(const std::string path, const std::string ref)
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

/**
 * @brief Builds check operations
 *
 * @param input_observable
 * @param input_json
 * @return Op_t
 */
Op_t buildCheck(const json::Value & def)
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
        return buildCheckVal(def);

    switch (v->value.GetString()[0])
    {
        case FUNCTION_HELPER_ANCHOR:
            return buildCheckFH(v->name.GetString());
            break;
        case REFERENCE_ANCHOR:
            return buildCheckRef(v->name.GetString(), v->value.GetString());
            break;
        default:
            return buildCheckVal(def);
    }
};

} // namespace builder::internals::builders

#endif // _BUILDERS_CHECK_H
