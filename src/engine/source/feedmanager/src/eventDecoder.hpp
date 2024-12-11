/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EVENT_DECODER_HPP
#define _EVENT_DECODER_HPP

#include "base/logging.hpp"
#include "base/utils/chainOfResponsability.hpp"
#include "base/utils/stringUtils.hpp"
#include "cve5_generated.h"
#include "cve5_schema.h"
#include "eventContext.hpp"
#include "flatbuffers/idl.h"
#include "packageTranslation_generated.h"
#include "packageTranslation_schema.h"

const static std::map<ResourceType, const char*> SCHEMA = {{ResourceType::CVE, cve5_SCHEMA},
                                                           {ResourceType::TRANSLATION, packageTranslation_SCHEMA},
                                                           {ResourceType::VENDOR_MAP, nullptr},
                                                           {ResourceType::OSCPE_RULES, nullptr},
                                                           {ResourceType::CNA_MAPPING, nullptr}};

const static std::map<ResourceType, const char*> COLUMNS = {{ResourceType::CVE, "cve5"},
                                                            {ResourceType::TRANSLATION, "translation"},
                                                            {ResourceType::VENDOR_MAP, "vendor_map"},
                                                            {ResourceType::OSCPE_RULES, "oscpe_rules"},
                                                            {ResourceType::CNA_MAPPING, "cna_mapping"}};

/**
 * @brief EventDecoder class.
 *
 */
class EventDecoder final : public utils::patterns::AbstractHandler<std::shared_ptr<EventContext>>
{
private:
    /**
     * @brief Process a CVE5 or Translation message.
     *
     * @param data Event context.
     */
    void processEvent(std::shared_ptr<EventContext> data) const
    {
        if (data->resource.contains("resource"))
        {
            if (base::utils::string::startsWith(data->resource.at("resource").get<std::string_view>(), "TID-"))
            {
                data->resourceType = ResourceType::TRANSLATION;
            }
            else if (base::utils::string::startsWith(data->resource.at("resource").get<std::string_view>(), "CVE-"))
            {
                data->resourceType = ResourceType::CVE;
            }
            else if (base::utils::string::startsWith(data->resource.at("resource").get<std::string_view>(),
                                                     "FEED-GLOBAL"))
            {
                data->resourceType = ResourceType::VENDOR_MAP;
            }
            else if (base::utils::string::startsWith(data->resource.at("resource").get<std::string_view>(),
                                                     "OSCPE-GLOBAL"))
            {
                data->resourceType = ResourceType::OSCPE_RULES;
            }
            else if (base::utils::string::startsWith(data->resource.at("resource").get<std::string_view>(),
                                                     "CNA-MAPPING-GLOBAL"))
            {
                data->resourceType = ResourceType::CNA_MAPPING;
            }
            else
            {
                LOG_ERROR("Invalid resource type: {}.", data->resource.at("resource").get_ref<const std::string&>());
                return;
            }

            auto schema = SCHEMA.at(data->resourceType);
            auto column = COLUMNS.at(data->resourceType);

            for (const auto& [resourceType, columnFamilyName] : COLUMNS)
            {
                if (!data->feedDatabase->columnExists(columnFamilyName))
                {
                    data->feedDatabase->createColumn(columnFamilyName);
                }
            }

            if ("create" == data->resource.at("type"))
            {
                if (!schema)
                {
                    // Resources in JSON format.
                    data->feedDatabase->put(
                        data->resource.at("resource"), data->resource.at("payload").dump().c_str(), column);
                }
                else
                {
                    // Resources in flatbuffer format.
                    flatbuffers::Parser parser;

                    if (!parser.Parse(schema) || !parser.Parse(data->resource.at("payload").dump().c_str()))
                    {
                        throw std::runtime_error("Unable to parse payload: " + parser.error_);
                    }

                    rocksdb::Slice flatbufferResource(reinterpret_cast<const char*>(parser.builder_.GetBufferPointer()),
                                                      parser.builder_.GetSize());
                    data->feedDatabase->put(data->resource.at("resource"), flatbufferResource, column);
                    if (data->resourceType == ResourceType::CVE)
                    {
                        flatbuffers::FlatBufferBuilder& builder = parser.builder_;
                        data->cve5Buffer = builder.Release();
                    }
                }
            }

            else if ("update" == data->resource.at("type"))
            {
                rocksdb::PinnableSlice slice;
                if (!data->feedDatabase->get(data->resource.at("resource"), slice, column))
                {
                    throw std::runtime_error("Unable to find resource.");
                }

                if (!schema)
                {
                    // Resources in JSON format.
                    auto jsonData = nlohmann::json::parse(slice.data());
                    jsonData.patch_inplace(data->resource.at("operations"));
                    data->feedDatabase->put(data->resource.at("resource"), jsonData.dump(), column);
                }
                else
                {
                    // Resources in flatbuffer format.
                    flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(slice.data()), slice.size());
                    switch (data->resourceType)
                    {
                        default: throw std::runtime_error("Invalid resource type.");

                        case ResourceType::CVE:
                            if (!cve_v5::VerifyEntryBuffer(verifier))
                            {
                                throw std::runtime_error(
                                    "Error getting CVEv5 Entry object from rocksdb. FlatBuffers verifier failed");
                            }
                            break;

                        case ResourceType::TRANSLATION:
                            if (!NSVulnerabilityScanner::VerifyTranslationEntryBuffer(verifier))
                            {
                                throw std::runtime_error(
                                    "Error getting TranslationEntry object from rocksdb. FlatBuffers verifier failed");
                            }
                            break;
                    }
                    flatbuffers::IDLOptions options;
                    options.output_default_scalars_in_json = true;
                    options.strict_json = true;
                    flatbuffers::Parser parser(options);
                    parser.Parse(schema);

                    std::string strData;
                    flatbuffers::GenText(parser, reinterpret_cast<const uint8_t*>(slice.data()), &strData);
                    auto jsonData = nlohmann::json::parse(strData);

                    jsonData.patch_inplace(data->resource.at("operations"));
                    if (!parser.Parse(jsonData.dump().c_str()))
                    {
                        throw std::runtime_error("Unable to parse patched data: " + parser.error_);
                    }

                    rocksdb::Slice flatbufferResource(reinterpret_cast<const char*>(parser.builder_.GetBufferPointer()),
                                                      parser.builder_.GetSize());

                    data->feedDatabase->put(data->resource.at("resource"), flatbufferResource, column);

                    if (data->resourceType == ResourceType::CVE)
                    {
                        flatbuffers::FlatBufferBuilder& builder = parser.builder_;
                        data->cve5Buffer = builder.Release();
                    }
                }
            }
            // TODO: This is not fully supported and needs revision.
            else if ("delete" == data->resource.at("type"))
            {
                if (data->resourceType == ResourceType::TRANSLATION)
                {
                    data->feedDatabase->delete_(data->resource.at("resource"), column);
                }
            }
            else
            {
                throw std::runtime_error("Unknown event type");
            }
        }
        else
        {
            throw std::runtime_error("Missing key 'resource'.");
        }
    }

public:
    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Event context.
     * @return std::shared_ptr<EventContext> Abstract handler.
     */
    std::shared_ptr<EventContext> handleRequest(std::shared_ptr<EventContext> data) override
    {
        processEvent(data);

        // Only CVEs need more processing because needs convert the model.
        if (data->resourceType == ResourceType::CVE)
        {
            return utils::patterns::AbstractHandler<std::shared_ptr<EventContext>>::handleRequest(std::move(data));
        }
        return nullptr;
    }
};

#endif // _EVENT_DECODER_HPP
