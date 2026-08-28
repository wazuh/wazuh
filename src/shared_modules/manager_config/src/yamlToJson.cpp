/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#include "yamlToJson.hpp"

#include <yaml-cpp/anchor.h>
#include <yaml-cpp/emitterstyle.h>
#include <yaml-cpp/eventhandler.h>
#include <yaml-cpp/mark.h>
#include <yaml-cpp/parser.h>
#include <yaml-cpp/yaml.h>

#include <cerrno>
#include <cstdlib>
#include <regex>
#include <sstream>

namespace manager_config::detail
{
    namespace
    {

        /// Walks the event stream once to reject what the Node API resolves silently (aliases, anchors, tags)
        /// and to count documents.
        class StrictnessHandler final : public YAML::EventHandler
        {
        public:
            std::size_t documents {0};
            std::optional<std::string> problem;

            void OnDocumentStart(const YAML::Mark&) override
            {
                ++documents;
            }
            void OnDocumentEnd() override {}
            void OnNull(const YAML::Mark& mark, YAML::anchor_t anchor) override
            {
                checkAnchor(mark, anchor);
            }
            void OnAlias(const YAML::Mark& mark, YAML::anchor_t) override
            {
                fail(mark, "aliases (*name) are not allowed");
            }
            void
            OnScalar(const YAML::Mark& mark, const std::string& tag, YAML::anchor_t anchor, const std::string&) override
            {
                checkAnchor(mark, anchor);
                checkTag(mark, tag);
            }
            void OnSequenceStart(const YAML::Mark& mark,
                                 const std::string& tag,
                                 YAML::anchor_t anchor,
                                 YAML::EmitterStyle::value) override
            {
                checkAnchor(mark, anchor);
                checkTag(mark, tag);
            }
            void OnSequenceEnd() override {}
            void OnMapStart(const YAML::Mark& mark,
                            const std::string& tag,
                            YAML::anchor_t anchor,
                            YAML::EmitterStyle::value) override
            {
                checkAnchor(mark, anchor);
                checkTag(mark, tag);
            }
            void OnMapEnd() override {}

        private:
            void fail(const YAML::Mark& mark, const std::string& what)
            {
                if (!problem)
                {
                    problem = "line " + std::to_string(mark.line + 1) + ": " + what;
                }
            }
            void checkAnchor(const YAML::Mark& mark, YAML::anchor_t anchor)
            {
                if (anchor != YAML::NullAnchor)
                {
                    fail(mark, "anchors (&name) are not allowed");
                }
            }
            void checkTag(const YAML::Mark& mark, const std::string& tag)
            {
                // yaml-cpp reports "?" for plain scalars, "!" for quoted scalars and "" when no tag applies.
                if (!tag.empty() && tag != "?" && tag != "!")
                {
                    fail(mark, "explicit tags (" + tag + ") are not allowed");
                }
            }
        };

        const std::regex INT_RE {"^[-+]?(0|[1-9][0-9]*)$"};
        const std::regex FLOAT_RE {"^[-+]?(\\.[0-9]+|[0-9]+(\\.[0-9]*)?)([eE][-+]?[0-9]+)?$"};

        /// YAML 1.2 core schema resolution for a plain scalar.
        void scalarToJson(const YAML::Node& node, rapidjson::Value& out, rapidjson::Document::AllocatorType& allocator)
        {
            const std::string& text = node.Scalar();
            const bool quoted = node.Tag() == "!";
            if (!quoted)
            {
                if (text == "true" || text == "True" || text == "TRUE")
                {
                    out.SetBool(true);
                    return;
                }
                if (text == "false" || text == "False" || text == "FALSE")
                {
                    out.SetBool(false);
                    return;
                }
                if (text.empty() || text == "~" || text == "null" || text == "Null" || text == "NULL")
                {
                    out.SetNull();
                    return;
                }
                if (std::regex_match(text, INT_RE))
                {
                    errno = 0;
                    const long long value = std::strtoll(text.c_str(), nullptr, 10);
                    if (errno == 0)
                    {
                        out.SetInt64(value);
                        return;
                    }
                }
                if (std::regex_match(text, FLOAT_RE) || text == ".inf" || text == "-.inf" || text == ".nan")
                {
                    errno = 0;
                    const double value = std::strtod(text.c_str(), nullptr);
                    if (errno == 0)
                    {
                        out.SetDouble(value);
                        return;
                    }
                }
            }
            out.SetString(text.c_str(), static_cast<rapidjson::SizeType>(text.size()), allocator);
        }

        std::optional<Error> nodeToJson(const YAML::Node& node,
                                        rapidjson::Value& out,
                                        rapidjson::Document::AllocatorType& allocator,
                                        const std::string& pointer,
                                        int depth)
        {
            if (depth > MAX_YAML_DEPTH)
            {
                return Error {pointer, "document nested deeper than " + std::to_string(MAX_YAML_DEPTH) + " levels"};
            }
            switch (node.Type())
            {
                case YAML::NodeType::Null:
                case YAML::NodeType::Undefined: out.SetNull(); return std::nullopt;
                case YAML::NodeType::Scalar: scalarToJson(node, out, allocator); return std::nullopt;
                case YAML::NodeType::Sequence:
                {
                    out.SetArray();
                    std::size_t index = 0;
                    for (const auto& item : node)
                    {
                        rapidjson::Value value;
                        if (auto error =
                                nodeToJson(item, value, allocator, pointer + "/" + std::to_string(index), depth + 1))
                        {
                            return error;
                        }
                        out.PushBack(value, allocator);
                        ++index;
                    }
                    return std::nullopt;
                }
                case YAML::NodeType::Map:
                {
                    out.SetObject();
                    for (const auto& entry : node)
                    {
                        if (!entry.first.IsScalar())
                        {
                            return Error {pointer, "mapping keys must be scalars"};
                        }
                        const std::string key = entry.first.Scalar();
                        if (out.HasMember(key.c_str()))
                        {
                            return Error {pointer + "/" + key, "duplicate key"};
                        }
                        rapidjson::Value value;
                        if (auto error = nodeToJson(entry.second, value, allocator, pointer + "/" + key, depth + 1))
                        {
                            return error;
                        }
                        rapidjson::Value name(key.c_str(), static_cast<rapidjson::SizeType>(key.size()), allocator);
                        out.AddMember(name, value, allocator);
                    }
                    return std::nullopt;
                }
            }
            return Error {pointer, "unsupported YAML node"};
        }

    } // namespace

    std::optional<Error> yamlToJson(std::string_view yamlText, rapidjson::Document& out)
    {
        if (yamlText.size() > MAX_YAML_BYTES)
        {
            return Error {"", "configuration file larger than " + std::to_string(MAX_YAML_BYTES) + " bytes"};
        }
        try
        {
            std::stringstream stream {std::string {yamlText}};
            YAML::Parser parser(stream);
            StrictnessHandler handler;
            while (parser.HandleNextDocument(handler))
            {
                if (handler.problem)
                {
                    return Error {"", *handler.problem};
                }
            }
            if (handler.documents > 1)
            {
                return Error {
                    "", "exactly one YAML document is expected (found " + std::to_string(handler.documents) + ")"};
            }

            const YAML::Node root = YAML::Load(std::string {yamlText});
            out.SetObject();
            if (!root.IsDefined() || root.IsNull())
            {
                return std::nullopt; // empty file / only comments: every option takes its default
            }
            // A non-mapping root is left to the schema ("type" at pointer ""), like the Python validator does.
            rapidjson::Value value;
            if (auto error = nodeToJson(root, value, out.GetAllocator(), "", 1))
            {
                return error;
            }
            out.Swap(value);
            return std::nullopt;
        }
        catch (const YAML::Exception& e)
        {
            return Error {"", std::string {"YAML syntax error: "} + e.what()};
        }
    }

} // namespace manager_config::detail
