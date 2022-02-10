/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "buildMap.hpp"

using namespace builder::internals::builders;

Op_t builder::internals::builders::buildMapVal(const json::Value & def)
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

Op_t builder::internals::builders::buildMapRef(const std::string path, const std::string ref)
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
Op_t builder::internals::builders::buildMap(const json::Value & def)
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
