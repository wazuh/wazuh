#ifndef _BUILDERS_STAGE_H
#define _BUILDERS_STAGE_H

#include <stdexcept>
#include <vector>

#include "connectable.hpp"
#include "json.hpp"
#include "rxcpp/rx.hpp"

namespace builder::internals::builders
{
// The type of the event which will flow through the stream
using Event_t = json::Document;
// The type of the observable which will compose the processing graph
using Obs_t = rxcpp::observable<Event_t>;
// The type of a connectable operation
using Op_t = std::function<Obs_t(const Obs_t &)>;
// The signature of a builder function which will build an operation from
// a piece of an asset description.
using Builder_t = std::function<Op_t(const json::Value &)>;

/**
 * @brief build a stage into an operation mergin all sub-operations
 * into one. All suboperations receive the same input, and their
 * outputs are merged into a single output in a fan-in.
 *
 * All operations of the stage must be the same type, until the registry
 * is done.
 *
 * @param def stage definition
 * @param make maker function which transform an stage element into
 * an operation
 * @return Op_t
 */
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

/**
 * @brief build a stage into an operation linking all sub-operations
 * into a chain. The output of an operation is the input of the next
 * one in the order on which they were defined.
 *
 * All operations of the stage must be the same type, until the registry
 * is done.
 *
 * @param def stage definition
 * @param make maker function which transform an stage element into
 * an operation
 * @return Op_t
 */
Op_t buildStageChain(const json::Value * def, Builder_t make)
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

} // namespace builder::internals::builders

#endif // _BUILDERS_STAGE_H
