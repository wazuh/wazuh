/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stub_image_reader.hpp"

namespace containerimages
{
    int StubImageReader::s_scanCount = 0;

    std::string StubImageReader::sourceType() const
    {
        return "local";
    }

    ImageReadResult StubImageReader::discover()
    {
        const int scan = s_scanCount++;

        ImageReferenceRecord reference;
        reference.source = {"local", "debian:12"};
        reference.tag = "12";
        reference.tags = {"12", "bookworm", "latest"};
        reference.configDigest = "sha256:debian-config-aaaa";
        reference.manifestDigest = "sha256:debian-manifest-aaaa";
        reference.os = "linux";
        reference.architecture = "amd64";
        reference.osVersion = "12";

        // Stable package, present in every scan.
        ImagePackageRecord apt;
        apt.name = "apt";
        apt.version = "2.6.1";
        apt.architecture = "amd64";
        apt.type = "deb";
        apt.vendor = "Debian";
        apt.description = "commandline package manager";
        apt.source = "apt";
        apt.installed = "2026-01-15T09:12:44Z";
        apt.path = "/usr/bin/apt";
        apt.category = "admin";
        apt.priority = "required";
        apt.multiarch = "same";
        apt.packageDbPath = "var/lib/dpkg/status";
        apt.size = 4276224;
        reference.packages.push_back(apt);

        // Package whose version changes on the second scan (drives a MODIFY delta).
        ImagePackageRecord baseFiles;
        baseFiles.name = "base-files";
        baseFiles.architecture = "amd64";
        baseFiles.type = "deb";
        baseFiles.vendor = "Debian";
        baseFiles.packageDbPath = "var/lib/dpkg/status";
        baseFiles.version = (scan == 0) ? "12.4+deb12u10" : "12.4+deb12u11";
        baseFiles.size = 442368;
        reference.packages.push_back(baseFiles);

        if (scan == 0)
        {
            // Package present only on the first scan (drives a DELETE delta on the next scan).
            ImagePackageRecord transitional;
            transitional.name = "perl-base";
            transitional.version = "5.36.0-7";
            transitional.architecture = "amd64";
            transitional.type = "deb";
            transitional.vendor = "Debian";
            transitional.packageDbPath = "var/lib/dpkg/status";
            transitional.size = 7657472;
            reference.packages.push_back(transitional);
        }
        else
        {
            // Package added from the second scan onward (drives a CREATE delta).
            ImagePackageRecord added;
            added.name = "curl";
            added.version = "7.88.1-10";
            added.architecture = "amd64";
            added.type = "deb";
            added.vendor = "Debian";
            added.packageDbPath = "var/lib/dpkg/status";
            added.size = 462848;
            reference.packages.push_back(added);
        }

        return ImageReadResult::success({reference});
    }
} // namespace containerimages
