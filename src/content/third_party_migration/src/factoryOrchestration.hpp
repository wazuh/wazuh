/*
 * Wazuh migration.
 * Copyright (C) 2015, Wazuh Inc.
 * June 17, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_ORCHESTRATION_HPP
#define _FACTORY_ORCHESTRATION_HPP
#include "chainOfResponsability.hpp"
#include "jsonParser.hpp"
#include "NVD/normalizerNVD.hpp"
#include "diffEngine.hpp"
#include <memory>

class FactoryOrchestration final
{
    public:
        static std::shared_ptr<AbstractHandler<std::shared_ptr<MigrationContext>>> create(const std::string& orchestrationType)
        {
            if (orchestrationType.compare("nvd") == 0)
            {
                auto jsonParser { std::make_shared<JsonParser>() };
                auto normalizerNVD { std::make_shared<NormalizerNVD>() };
                auto diffEngine { std::make_shared<DiffEngine>() };

                jsonParser->setNext(normalizerNVD)->setNext(diffEngine);

                return jsonParser;
            }
            else
            {
                throw std::runtime_error { "Invalid orchestration type: " + orchestrationType };
            }
        }
};

#endif //_FACTORY_ORCHESTRATION_HPP
