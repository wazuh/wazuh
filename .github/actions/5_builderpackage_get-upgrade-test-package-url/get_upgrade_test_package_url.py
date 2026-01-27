#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Module providing a function to get the url of a Wazuh package based on
different parameters.
"""
import argparse

def _get_release_architecture(system: str, architecture: str) -> str | None:
    """Returns the previous stable version for the given arguments.
    Args:
        system: (str): for linux packages, packages manager system:
            [rpm, deb].
        architecture: (str): package architecture one of following:
            [amd64, intel64, arm64, armhf, i386, ppc64].
    Returns:
        arch: (str): Released package arc.
    """

    match system:
        case "deb":
            match architecture:
                case "ppc64":
                    arch = "ppc64el"
                case "x86_64":
                    arch = "amd64"
                case "aarch64":
                    arch = "arm64"
                case _:
                    arch = architecture
            return arch
        case "rpm":
            match architecture:
                case "amd64":
                    arch = "x86_64"
                case "arm64":
                    arch = "aarch64"
                case "armhf":
                    arch = "armv7hl"
                case "ppc64":
                    arch = "ppc64le"
                case "i386":
                    arch = "i386"
                case _:
                    arch = architecture
            return arch
        case _:
            return None

def get_release_package_url(component: str, os: str, system: str,
                            wazuh_version: str, architecture: str) -> str | None:
    """Returns the previous stable version for the given arguments.
    Args:
        component: (str): wazuh component type, one of following:
            [manager, agent].
        os: (str): OS of the requested package url, one of following:
            [linux, macos, windows].
        system: (str): for linux packages, packages manager system:
            [rpm, deb].
        wazuh_version: (str): version of the package we are looking for.
        architecture: (str): package architecture one of following:
            [amd64, intel64, arm64, armhf, i386, ppc64, sparc].
    Returns:
        url: (str): Released package url.
    """
    wazuh_major=wazuh_version[0]

    match component:
        case "manager":
            system_url = "yum" if system == "rpm" else "apt/pool/main/w"
            architecture_separator = "." if system == "rpm" else "_"
            release_architecture = _get_release_architecture(system,
                                                             architecture)
            url = (
                f"https://packages.wazuh.com/{wazuh_major}.x/{system_url}"
                f"/wazuh-{component}-/{wazuh_version}-1{architecture_separator}"
                f"{release_architecture}.{system}"
            )
        case "agent":
            match os:
                case "linux":
                    architecture = architecture or "amd64"
                    system_url = "yum" if system == "rpm" else "apt/pool/main/w/wazuh-agent"
                    architecture_separator = "." if system == "rpm" else "_"
                    version_separator = "-" if system == "rpm" else "_"
                    release_architecture = _get_release_architecture(system,
                                                             architecture)
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/{system_url}"
                        f"/wazuh-{component}{version_separator}{wazuh_version}-1"
                        f"{architecture_separator}{release_architecture}.{system}"
                    )
                case "windows":
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/windows/"
                        f"wazuh-{component}-{wazuh_version}-1.msi"
                    )
                case "macos":
                    architecture = "arm64" if architecture == "arm64" else "intel64"
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/macos/"
                        f"wazuh-{component}-{wazuh_version}-1.{architecture}.pkg"
                    )
        case _:
            return None

    return url


def main():
    """Main function."""
    script_description = (
        "Get the package url for the received arguments."
    )

    parser = argparse.ArgumentParser(description=script_description)
    parser.add_argument("-c", "--component", type=str, action="store",
                        required=True, choices = ["manager", "agent"],
                        help="Wazuh component type.")
    parser.add_argument("-o",  "--os", type=str, action="store",
                        required=True, choices = ["linux", "macos", "windows"],
                        help="OS of the requested package url.")
    parser.add_argument("-s", "--system", type=str, action="store",
                        required=False, choices = ["rpm", "deb", ""],
                        help="Linux package manager system.")
    parser.add_argument("-v", "--version", type=str, action="store",
                        required=True, help="Wazuh component version.")
    parser.add_argument("-a", "--architecture", type=str, action="store",
                        required=False, choices = ["amd64", "intel64", "arm64",
                        "armhf", "i386", "ppc64", "sparc", ""],
                        help="Wazuh component architecture")

    args = parser.parse_args()

    print(get_release_package_url(args.component, args.os, args.system,
                                  args.version, args.architecture))

if __name__ == "__main__":
    main()
