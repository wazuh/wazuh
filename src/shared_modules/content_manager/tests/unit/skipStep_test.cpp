/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "skipStep_test.hpp"
#include "skipStep.hpp"
#include "updaterContext.hpp"
#include <filesystem>
#include <memory>

TEST_F(SkipStepTest, CheckBehaviour)
{
    auto updaterContext {std::make_shared<UpdaterContext>()};

    EXPECT_FALSE(updaterContext->data.empty());

    SkipStep skipStep;
    skipStep.registerPreAction(
        [](std::shared_ptr<UpdaterContext> context)
        {
            // delete the data content
            context->data.clear();
        });

    EXPECT_NO_THROW(skipStep.handleRequest(updaterContext));

    EXPECT_TRUE(updaterContext->data.empty());
}
