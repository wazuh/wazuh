/*
 * Wazuh Migration
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _JSON_PARSER_HPP
#define _JSON_PARSER_HPP

#include "chainOfResponsability.hpp"
#include "migrationContext.hpp"
#include <iostream>

class JsonParser final : public AbstractHandler<std::shared_ptr<MigrationContext>>
{
    private:
        void loadData(std::shared_ptr<MigrationContext> context) const;

    public:
        virtual std::shared_ptr<MigrationContext> handleRequest(std::shared_ptr<MigrationContext> data) override
        {
            std::cout << "JsonParser" << std::endl;
            loadData(data);
            return AbstractHandler<std::shared_ptr<MigrationContext>>::handleRequest(data);
        }
};

#endif // _JSON_PARSER_HPP
