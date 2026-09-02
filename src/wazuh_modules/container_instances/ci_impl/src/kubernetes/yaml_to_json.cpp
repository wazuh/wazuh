#include "yaml_to_json.hpp"

#include <yaml.h>

namespace wazuh::container_instances
{

    namespace
    {

        struct Parser
        {
            yaml_parser_t parser {};

            Parser()
            {
                if (yaml_parser_initialize(&parser) == 0)
                {
                    throw YamlParseError("yaml parser initialization failed");
                }
            }

            Parser(const Parser&) = delete;
            Parser& operator=(const Parser&) = delete;
            Parser(Parser&&) = delete;
            Parser& operator=(Parser&&) = delete;

            ~Parser()
            {
                yaml_parser_delete(&parser);
            }
        };

        struct EventGuard
        {
            yaml_event_t event {};

            EventGuard() = default;
            EventGuard(const EventGuard&) = delete;
            EventGuard& operator=(const EventGuard&) = delete;
            EventGuard(EventGuard&&) = delete;
            EventGuard& operator=(EventGuard&&) = delete;

            ~EventGuard()
            {
                yaml_event_delete(&event);
            }
        };

        nlohmann::json scalarToJson(const yaml_event_t& event)
        {
            const auto* value = reinterpret_cast<const char*>(event.data.scalar.value);
            std::string text {value, event.data.scalar.length};

            if (event.data.scalar.style == YAML_PLAIN_SCALAR_STYLE)
            {
                if (text == "true")
                {
                    return true;
                }
                if (text == "false")
                {
                    return false;
                }
            }
            return text;
        }

        // NOLINTBEGIN(misc-no-recursion): recursion depth is bounded by the document
        // nesting level, and kubeconfigs are a few levels deep at most.
        nlohmann::json parseNode(yaml_parser_t& parser, const yaml_event_t& startEvent);

        nlohmann::json parseMapping(yaml_parser_t& parser)
        {
            auto object = nlohmann::json::object();
            while (true)
            {
                EventGuard key;
                if (yaml_parser_parse(&parser, &key.event) == 0)
                {
                    throw YamlParseError("malformed YAML mapping");
                }
                if (key.event.type == YAML_MAPPING_END_EVENT)
                {
                    return object;
                }
                if (key.event.type != YAML_SCALAR_EVENT)
                {
                    throw YamlParseError("unsupported YAML mapping key");
                }
                const std::string keyName {reinterpret_cast<const char*>(key.event.data.scalar.value),
                                           key.event.data.scalar.length};

                EventGuard value;
                if (yaml_parser_parse(&parser, &value.event) == 0)
                {
                    throw YamlParseError("malformed YAML mapping value");
                }
                object[keyName] = parseNode(parser, value.event);
            }
        }

        nlohmann::json parseSequence(yaml_parser_t& parser)
        {
            auto array = nlohmann::json::array();
            while (true)
            {
                EventGuard item;
                if (yaml_parser_parse(&parser, &item.event) == 0)
                {
                    throw YamlParseError("malformed YAML sequence");
                }
                if (item.event.type == YAML_SEQUENCE_END_EVENT)
                {
                    return array;
                }
                array.push_back(parseNode(parser, item.event));
            }
        }

        nlohmann::json parseNode(yaml_parser_t& parser, const yaml_event_t& startEvent)
        {
            switch (startEvent.type)
            {
                case YAML_SCALAR_EVENT: return scalarToJson(startEvent);
                case YAML_MAPPING_START_EVENT: return parseMapping(parser);
                case YAML_SEQUENCE_START_EVENT: return parseSequence(parser);
                case YAML_ALIAS_EVENT: throw YamlParseError("YAML aliases are not supported");
                default: throw YamlParseError("unexpected YAML event");
            }
        }
        // NOLINTEND(misc-no-recursion)

    } // namespace

    nlohmann::json yamlToJson(const std::string& yamlText)
    {
        Parser parser;
        yaml_parser_set_input_string(
            &parser.parser, reinterpret_cast<const unsigned char*>(yamlText.data()), yamlText.size());

        // STREAM_START, DOCUMENT_START, <root node>, DOCUMENT_END, STREAM_END.
        for (const auto expected : {YAML_STREAM_START_EVENT, YAML_DOCUMENT_START_EVENT})
        {
            EventGuard event;
            if (yaml_parser_parse(&parser.parser, &event.event) == 0 || event.event.type != expected)
            {
                throw YamlParseError("malformed YAML document");
            }
        }

        EventGuard root;
        if (yaml_parser_parse(&parser.parser, &root.event) == 0)
        {
            throw YamlParseError("malformed YAML document");
        }
        return parseNode(parser.parser, root.event);
    }

} // namespace wazuh::container_instances
