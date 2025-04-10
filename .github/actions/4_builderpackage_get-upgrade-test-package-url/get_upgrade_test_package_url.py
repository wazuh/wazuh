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
            if architecture == "ppc64":
                arch = "ppc64el"
            else:
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
            [linux, linux_legacy, macos, windows, solaris10, solaris11, aix, hp-ux].
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
                case "linux_legacy":
                    release_architecture = _get_release_architecture(system,
                                                             architecture)
                    system_url = f"yum5/{release_architecture}"
                    architecture_separator = "."
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/{system_url}"
                        f"/wazuh-{component}-{wazuh_version}-1{architecture_separator}"
                        f"{release_architecture}.{system}"
                    )
                case "windows":
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/windows/"
                        f"wazuh-{component}-{wazuh_version}-1.msi"
                    )
                case "macos":
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/macos/"
                        f"wazuh-{component}-{wazuh_version}-1.{architecture}.pkg"
                    )
                case "solaris10":
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/solaris/"
                        f"{architecture}/10/wazuh-{component}_v{wazuh_version}-"
                        f"sol10-{architecture}.pkg"
                    )
                case "solaris11":
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/solaris/"
                        f"{architecture}/11/wazuh-{component}_v{wazuh_version}-"
                        f"sol11-{architecture}.p5p"
                    )
                case "aix":
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/aix/"
                        f"wazuh-{component}-{wazuh_version}-1.aix.ppc.rpm"
                    )
                case "hp-ux":
                    url = (
                        f"https://packages.wazuh.com/{wazuh_major}.x/hp-ux/"
                        f"wazuh-{component}-{wazuh_version}-1-hpux-11v3-ia64.tar.gz"
                    )
        case _:
            return None

    return url


def main():
    """Main function."""
    script_description = (
        "Get tha package url for the received arguments."
    )

    parser = argparse.ArgumentParser(description=script_description)
    parser.add_argument("-c", "--component", type=str, action="store",
                        required=True, choices = ["manager", "agent"],
                        help="Wazuh component type.")
    parser.add_argument("-o",  "--os", type=str, action="store",
                        required=True, choices = ["linux", "linux_legacy",
                        "macos", "windows", "solaris10", "solaris11", "aix", 
                        "hp-ux"], help="OS of the requested package url.")
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
