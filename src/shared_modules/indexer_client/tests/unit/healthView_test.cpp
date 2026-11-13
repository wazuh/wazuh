/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// HealthView::noUsableAfterProbes(), the "every node probed, none usable" check the engine's remote
// configuration read and the content manager's adapter share. Mutants: the empty check dropped, anyUsable() replaced by
// anyAvailable(), an unprobed node skipped instead of ending the check, the separator or the order changed.

#include <gtest/gtest.h>

#include "indexer_client/types.hpp"

using indexer_client::HealthView;

namespace
{
    HealthView::Node node(std::string url, HealthView::NodeState state, std::string reason)
    {
        return HealthView::Node {std::move(url), state, std::move(reason)};
    }
} // namespace

TEST(HealthViewTest, NoUsableAfterProbesWithoutNodes)
{
    HealthView view;
    EXPECT_FALSE(view.noUsableAfterProbes().has_value());
}

TEST(HealthViewTest, NoUsableAfterProbesWithAUsableNode)
{
    // A Throttled node is usable (the lenient aggregate), even when it is not Available. It carries a reason here so
    // that only its state, not an empty reason, ends the check.
    HealthView view;
    view.nodes.push_back(node("http://node-1:9200", HealthView::NodeState::Down, "connect: refused"));
    view.nodes.push_back(node("http://node-2:9200", HealthView::NodeState::Throttled, "status 429"));
    EXPECT_FALSE(view.noUsableAfterProbes().has_value());
}

TEST(HealthViewTest, NoUsableAfterProbesBeforeTheFirstProbe)
{
    // One node not probed yet (Down without a reason): the call may still wait for it, wherever it is in the list.
    HealthView view;
    view.nodes.push_back(node("http://node-1:9200", HealthView::NodeState::Down, "connect: refused"));
    view.nodes.push_back(node("http://node-2:9200", HealthView::NodeState::Down, ""));
    EXPECT_FALSE(view.noUsableAfterProbes().has_value());

    std::swap(view.nodes.front(), view.nodes.back());
    EXPECT_FALSE(view.noUsableAfterProbes().has_value());
}

TEST(HealthViewTest, NoUsableAfterProbesEveryNodeDown)
{
    HealthView view;
    view.nodes.push_back(node("http://node-1:9200", HealthView::NodeState::Down, "connect: refused"));
    view.nodes.push_back(node("http://node-2:9200", HealthView::NodeState::Down, "status 503"));
    view.nodes.push_back(node("http://node-3:9200", HealthView::NodeState::Down, "timeout"));
    const auto why = view.noUsableAfterProbes();
    ASSERT_TRUE(why.has_value());
    EXPECT_EQ(*why,
              "http://node-1:9200: connect: refused; http://node-2:9200: status 503; http://node-3:9200: timeout");
}
