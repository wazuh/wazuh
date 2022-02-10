/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "buildCheck.hpp"

using namespace builder::internals::builders;

using namespace builder::internals::syntax;

Obs_t builder::internals::builders::unit_op(Obs_t input)
{
    return input;
}

Op_t builder::internals::builders::buildCheckVal(const json::Value & def)
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

Op_t builder::internals::builders::buildCheckFH(const std::string path)
{
    return [=](Obs_t input) -> Obs_t
    {
        // std::cerr << "op() checkValBuilder built" << std::endl;
        return input.filter(
            [=](json::Document e)
            {
                // auto v = e.get(ref);
                return e.exists("/" + path);
            });
    };
}

Op_t builder::internals::builders::buildCheckRef(const std::string path, const std::string ref)
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

Op_t builder::internals::builders::buildCheck(const json::Value & def)
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
