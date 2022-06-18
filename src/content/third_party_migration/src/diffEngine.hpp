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


#ifndef _DIFFENGINE_HPP
#define _DIFFENGINE_HPP

#include "chainOfResponsability.hpp"
#include "migrationContext.hpp"
#include <iostream>

class DiffEngine final : public AbstractHandler<std::shared_ptr<MigrationContext>>
{
    private:
        void diffData(std::shared_ptr<MigrationContext> migrationContext) const;
    public:
        virtual std::shared_ptr<MigrationContext> handleRequest(std::shared_ptr<MigrationContext> data) override
        {
            std::cout << "DiffEngine" << std::endl;
            diffData(data);
            return AbstractHandler<std::shared_ptr<MigrationContext>>::handleRequest(data);
        }
};

#endif // _DIFFENGINE_HPP
