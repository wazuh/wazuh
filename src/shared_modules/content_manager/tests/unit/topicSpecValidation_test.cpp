/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "components/topicSpecValidation.hpp"
#include "contentTopicSpec.hpp"
#include "gtest/gtest.h"
#include <functional>
#include <string>
#include <variant>

using content_manager::CursorDetection;
using content_manager::DocumentProbe;
using content_manager::HashDetection;
using content_manager::QueryProbe;
using content_manager::Readiness;
using content_manager::TopicSpec;

namespace
{

    TopicSpec cursorSpec()
    {
        TopicSpec spec;
        spec.schedule.intervalSeconds = 3600;
        spec.source.indices = {".wazuh-threatintel-vulnerabilities"};
        spec.readiness = Readiness {".wazuh-cti-consumers", "cti:catalog:consumer:vulnerabilities", 30, 7};
        spec.detection = CursorDetection {};
        spec.fullLoad.requiredDocumentIds = {"FEED-GLOBAL"};
        return spec;
    }

    TopicSpec hashSpec()
    {
        TopicSpec spec;
        spec.source.indices = {"wazuh-threatintel-policies"};
        HashDetection hash;
        hash.probe = QueryProbe {nlohmann::json {{"wildcard", {{"_index", {{"value", "*policies*"}}}}}}};
        hash.tokenPointers = {"/space/hash/sha256"};
        hash.metadata = {{"enabled", "/document/enabled"}};
        spec.detection = hash;
        return spec;
    }

    /// Asserts @p spec, after @p breakIt, is rejected naming @p field.
    void expectRejected(TopicSpec spec, const std::function<void(TopicSpec&)>& breakIt, const std::string& field)
    {
        breakIt(spec);
        try
        {
            validateTopicSpec(spec);
            ADD_FAILURE() << "accepted a spec with a broken " << field;
        }
        catch (const std::invalid_argument& e)
        {
            EXPECT_NE(std::string {e.what()}.find(field), std::string::npos)
                << "message '" << e.what() << "' does not name '" << field << "'";
        }
    }

    HashDetection& hashOf(TopicSpec& spec)
    {
        return std::get<HashDetection>(spec.detection);
    }

} // namespace

TEST(TopicSpecValidationTest, AcceptsBothStrategiesAndTheDefaults)
{
    EXPECT_NO_THROW(validateTopicSpec(cursorSpec()));
    EXPECT_NO_THROW(validateTopicSpec(hashSpec()));

    TopicSpec minimal;
    minimal.source.indices = {"data-index"};
    EXPECT_NO_THROW(validateTopicSpec(minimal)) << "the defaults must form a valid registration";

    auto manifest = hashSpec();
    hashOf(manifest).probe = DocumentProbe {"__ioc_type_hashes__"};
    EXPECT_NO_THROW(validateTopicSpec(manifest));
}

TEST(TopicSpecValidationTest, RejectsAnUnusableSource)
{
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.source.indices.clear(); }, "source.indices");
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.source.indices = {""}; }, "source.indices");
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.source.pageSize = 0; }, "source.pageSize");
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.source.slices = 0; }, "source.slices");
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.source.pitKeepAlive.clear(); }, "source.pitKeepAlive");
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.source.query = nlohmann::json::array(); }, "source.query");
    expectRejected(
        cursorSpec(),
        [](TopicSpec& s) { s.source.sourceFilter = nlohmann::json::array({"offset"}); },
        "source.sourceFilter");
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.schedule.intervalSeconds = 0; }, "schedule.intervalSeconds");
}

TEST(TopicSpecValidationTest, AReadinessGateNeedsAConcreteIndexAndAnId)
{
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.readiness->consumerId.clear(); }, "readiness.consumerId");
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.readiness->retrySeconds = 0; }, "readiness.retrySeconds");

    // Both consumer-document defences compare against `_index`, which reports concrete names; a
    // pattern would never match and the leak would be silent.
    for (const auto* bad : {"", ".consumers-*", "a,b", "-excluded"})
    {
        expectRejected(
            cursorSpec(), [bad](TopicSpec& s) { s.readiness->consumerIndex = bad; }, "readiness.consumerIndex");
    }
}

TEST(TopicSpecValidationTest, HashDetectionNeedsAProbeAndUsablePointers)
{
    expectRejected(hashSpec(), [](TopicSpec& s) { hashOf(s).tokenPointers.clear(); }, "detection.tokenPointers");
    expectRejected(
        hashSpec(), [](TopicSpec& s) { hashOf(s).tokenPointers = {"space.hash"}; }, "detection.tokenPointers");
    expectRejected(hashSpec(), [](TopicSpec& s) { hashOf(s).tokenPointers = {"/"}; }, "detection.tokenPointers");
    expectRejected(
        hashSpec(),
        [](TopicSpec& s) { hashOf(s).metadata = {{"enabled", "document.enabled"}}; },
        "detection.metadata.enabled");
    expectRejected(hashSpec(), [](TopicSpec& s) { hashOf(s).probe = DocumentProbe {""}; }, "detection.probe.id");
    expectRejected(
        hashSpec(),
        [](TopicSpec& s) { hashOf(s).probe = QueryProbe {nlohmann::json::array()}; },
        "detection.probe.query");
}

TEST(TopicSpecValidationTest, RejectsAnUnusableCursorOrRequiredDocument)
{
    expectRejected(cursorSpec(), [](TopicSpec& s) { s.detection = CursorDetection {"", "long"}; }, "detection");
    expectRejected(
        cursorSpec(), [](TopicSpec& s) { s.fullLoad.requiredDocumentIds = {""}; }, "fullLoad.requiredDocumentIds");
}
