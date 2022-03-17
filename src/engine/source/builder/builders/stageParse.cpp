/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stageParse.hpp"

#include <stdexcept>
#include <string>
#include <vector>

#include <glog/logging.h>

#include "registry.hpp"
#include <hlp/hlp.hpp>

namespace builder::internals::builders
{

types::Lifter stageBuilderParse(const types::DocumentValue &def)
{
    // Assert value is as expected
    if (!def.IsObject())
    {
        std::string msg = "Stage parse builder, expected array but got " +
                          std::to_string(def.GetType());
        LOG(ERROR) << msg;
        throw std::invalid_argument(msg);
    }

    auto parseObj = def.GetObj();

    if (!parseObj["logql"].IsArray())
    {
        // TODO ERROR
        LOG(ERROR) << "Parse stage is ill formed.";
        throw std::invalid_argument(
            "Config format error. Check the parser section.");
    }

    auto const &logqlArr = parseObj["logql"];
    if (logqlArr.Empty())
    {
        // TODO error
        LOG(ERROR) << "No logQl expressions found.";
        throw std::invalid_argument("Must have some expressions configured.");
    }

    std::vector<types::Lifter> parsers;
    for (auto const &item : logqlArr.GetArray())
    {
        if (!item.IsObject())
        {
            LOG(ERROR) << "LogQl object is badly formatted.";
            throw std::invalid_argument(
                "Bad format trying to get parse expression ");
        }

        // TODO hard-coded 'event.original'
        auto logQlExpr = item["event.original"].GetString();

        ParserFn parseOp;
        try{
            parseOp = getParserOp(logQlExpr);
        }
        catch (std::exception &e)
        {
            const char *msg = "Stage [parse] builder encountered exception "
                            "parsing LogQLExpression.";
            LOG(ERROR) << msg << " From exception: " << e.what();
            std::throw_with_nested(std::runtime_error(msg));
        }

        auto newOp = [parserOp = std::move(parseOp)](types::Observable o)
        {
            return o.map(
                [parserOp = std::move(parserOp)](types::Event e)
                {
                    auto ev = e->get("/message");
                    if (!ev->IsString())
                    {
                        // TODO error
                        return e;
                    }

                    ParseResult result;
                    auto ok = parserOp(ev->GetString(), result);
                    if (!ok)
                    {
                        // TODO error
                        return e;
                    }

                    for (auto const &val : result)
                    {
                        auto name =
                            json::Document::preparePath(val.first.c_str());
                        e->set(name, {val.second.c_str(), e->getAllocator()});
                    }

                    return e;
                });
        };

        parsers.emplace_back(newOp);
    }

    try
    {
        auto check = std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.broadcast"))(parsers);
        return check;
    }
    catch (std::exception &e)
    {
        const char *msg = "Stage [parse] builder encountered exception "
                          "chaining all mappings.";
        LOG(ERROR) << msg << " From exception: " << e.what();
        std::throw_with_nested(std::runtime_error(msg));
    }
}

} // namespace builder::internals::builders
