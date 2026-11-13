/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry_profile.hpp"

#include <algorithm>
#include <vector>

namespace
{
    constexpr auto GHCR_HOST {"ghcr.io"};
    constexpr auto ECR_PUBLIC_HOST {"public.ecr.aws"};
    constexpr auto ECR_PRIVATE_INFIX {".dkr.ecr."};
    constexpr auto ECR_FIPS_INFIX {".dkr.ecr-fips."};
    constexpr std::size_t ACCOUNT_DIGITS {12};
    constexpr std::size_t MAX_REGION_LENGTH {32};

    // Longest first, so ".amazonaws.com.cn" is not read as ".amazonaws.com" plus a stray
    // label.
    const std::vector<std::string>& dnsSuffixes()
    {
        static const std::vector<std::string> suffixes {"amazonaws.com.cn", "amazonaws.com"};

        return suffixes;
    }

    bool endsWith(const std::string& text, const std::string& suffix)
    {
        return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    bool isLowerLetter(const char character)
    {
        return character >= 'a' && character <= 'z';
    }

    bool isDigit(const char character)
    {
        return character >= '0' && character <= '9';
    }
} // namespace

namespace containerimages
{
    bool isValidAwsRegion(const std::string& region)
    {
        if (region.empty() || region.size() > MAX_REGION_LENGTH)
        {
            return false;
        }

        std::vector<std::string> labels;
        std::string::size_type start {0};

        while (true)
        {
            const auto separator {region.find('-', start)};

            labels.push_back(region.substr(start, separator == std::string::npos ? separator : separator - start));

            if (separator == std::string::npos)
            {
                break;
            }

            start = separator + 1;
        }

        // "us-east-1": a two-letter geography, one or more lower-case words, a number.
        if (labels.size() < 3 || labels.front().size() != 2 || labels.back().empty() || labels.back().size() > 2)
        {
            return false;
        }

        const auto isWord = [](const std::string& label)
        {
            return !label.empty() && std::all_of(label.begin(), label.end(), isLowerLetter);
        };

        for (std::size_t index = 0; index + 1 < labels.size(); ++index)
        {
            if (!isWord(labels[index]))
            {
                return false;
            }
        }

        return std::all_of(labels.back().begin(), labels.back().end(), isDigit);
    }

    bool isSupportedAwsDnsSuffix(const std::string& suffix)
    {
        const auto& suffixes {dnsSuffixes()};

        return std::find(suffixes.begin(), suffixes.end(), suffix) != suffixes.end();
    }

    bool profileForHost(const std::string& host, RegistryProfile& profile, std::string& error)
    {
        profile = {};
        error.clear();

        if (host == GHCR_HOST)
        {
            profile.kind = RegistryKind::Ghcr;
            return true;
        }

        if (host == ECR_PUBLIC_HOST)
        {
            profile.kind = RegistryKind::EcrPublic;
            return true;
        }

        const auto isPrivateShaped {host.size() > ACCOUNT_DIGITS &&
                                    std::all_of(host.begin(), host.begin() + ACCOUNT_DIGITS, isDigit)};

        if (isPrivateShaped && host.compare(ACCOUNT_DIGITS, std::char_traits<char>::length(ECR_FIPS_INFIX), ECR_FIPS_INFIX) == 0)
        {
            error = "Amazon ECR FIPS endpoints are not supported, and the reference names '" + host + "'";
            return false;
        }

        if (isPrivateShaped &&
            host.compare(ACCOUNT_DIGITS, std::char_traits<char>::length(ECR_PRIVATE_INFIX), ECR_PRIVATE_INFIX) == 0)
        {
            const auto tail {host.substr(ACCOUNT_DIGITS + std::char_traits<char>::length(ECR_PRIVATE_INFIX))};

            for (const auto& suffix : dnsSuffixes())
            {
                if (!endsWith(tail, "." + suffix))
                {
                    continue;
                }

                const auto region {tail.substr(0, tail.size() - suffix.size() - 1)};

                if (!isValidAwsRegion(region))
                {
                    break;
                }

                profile.kind = RegistryKind::EcrPrivate;
                profile.region = region;
                profile.dnsSuffix = suffix;
                return true;
            }

            error = "the Amazon ECR registry '" + host + "' does not name a valid region";
            return false;
        }

        error = "only ghcr.io, public.ecr.aws and Amazon ECR private registries are supported, and the reference names '" +
                host + "'";
        return false;
    }
} // namespace containerimages
