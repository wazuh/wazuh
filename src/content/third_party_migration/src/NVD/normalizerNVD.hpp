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


#ifndef _NORMALIZER_NVD_HPP
#define _NORMALIZER_NVD_HPP

#include "chainOfResponsability.hpp"
#include "migrationContext.hpp"
#include <iostream>

class NormalizerNVD final : public AbstractHandler<std::shared_ptr<MigrationContext>>
{
    private:
        void normalize(std::shared_ptr<MigrationContext> context) const;
    public:
        virtual std::shared_ptr<MigrationContext> handleRequest(std::shared_ptr<MigrationContext> data) override
        {
            std::cout << "NormalizerNVD" << std::endl;
            normalize(data);
            return AbstractHandler<std::shared_ptr<MigrationContext>>::handleRequest(data);
        }
};

#endif // _NORMALIZER_NVD_HPP
